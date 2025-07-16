// noise_encryption.rs - Noise Protocol Framework implementation for BitChat
// Based on the Swift implementation from PR #244

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, Instant};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use x25519_dalek::{PublicKey, StaticSecret};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;


/// Debug macros matching the main.rs pattern
macro_rules! debug_noise_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::DEBUG_LEVEL as u8 >= crate::DebugLevel::Basic as u8 {
                println!("[NOISE] {}", format!($($arg)*));
            }
        }
    };
}

macro_rules! debug_noise_full_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::DEBUG_LEVEL as u8 >= crate::DebugLevel::Full as u8 {
                println!("[NOISE-FULL] {}", format!($($arg)*));
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
pub enum NoiseError {
    InvalidHandshakeState,
    InvalidMessage,
    DecryptionFailed,
    EncryptionFailed,
    InvalidPublicKey,
    SessionNotEstablished,
    RateLimitExceeded,
    MessageTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakePattern {
    XX,  // The pattern we're implementing
}

/// Represents the current state of a Noise handshake
pub struct NoiseHandshakeState {
    pattern: HandshakePattern,
    role: NoiseRole,
    step: u8,
    local_static: StaticSecret,
    local_ephemeral: Option<StaticSecret>, // Use StaticSecret instead of EphemeralSecret for cloning
    remote_static: Option<PublicKey>,
    remote_ephemeral: Option<PublicKey>,
    h: [u8; 32],  // Hash state
    ck: [u8; 32], // Chaining key
    k: Option<[u8; 32]>, // Current encryption key
}

impl NoiseHandshakeState {
    pub fn new(role: NoiseRole, pattern: HandshakePattern, local_static: StaticSecret) -> Self {
        let mut h = [0u8; 32];
        
        // Initialize with protocol name "Noise_XX_25519_ChaChaPoly_SHA256"
        let protocol_name = b"Noise_XX_25519_ChaChaPoly_SHA256";
        let ck = if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            h.copy_from_slice(&Sha256::digest(protocol_name)[..32]);
            h
        };
        
        Self {
            pattern,
            role,
            step: 0,
            local_static,
            local_ephemeral: None,
            remote_static: None,
            remote_ephemeral: None,
            h,
            ck,
            k: None,
        }
    }
    
    /// Validate a public key to prevent weak keys
    pub fn validate_public_key(key_bytes: &[u8]) -> Result<PublicKey, NoiseError> {
        if key_bytes.len() != 32 {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Check for all-zero or all-one keys
        if key_bytes.iter().all(|&b| b == 0x00) || key_bytes.iter().all(|&b| b == 0xFF) {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        
        Ok(PublicKey::from(key_array))
    }
    
    /// Mix hash for transcript integrity
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize()[..32]);
    }
    
    /// Mix key for key derivation
    fn mix_key(&mut self, ikm: &[u8]) {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.ck), ikm);
        let mut output = [0u8; 64];
        hkdf.expand(&[], &mut output).unwrap();
        
        self.ck.copy_from_slice(&output[..32]);
        self.k = Some(output[32..].try_into().unwrap());
    }
    
    /// Encrypt and authenticate data
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.k {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            
            // Use h[0:12] as nonce for deterministic encryption during handshake
            let nonce_bytes = &self.h[..12];
            let nonce = Nonce::from_slice(nonce_bytes);
            
            let ciphertext = cipher.encrypt(nonce, plaintext)
                .map_err(|_| NoiseError::EncryptionFailed)?;
                
            self.mix_hash(&ciphertext);
            Ok(ciphertext)
        } else {
            // No key yet, just update hash
            self.mix_hash(plaintext);
            Ok(plaintext.to_vec())
        }
    }
    
    /// Decrypt and verify data
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.k {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            
            // Use h[0:12] as nonce for deterministic decryption during handshake
            let nonce_bytes = &self.h[..12];
            let nonce = Nonce::from_slice(nonce_bytes);
            
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|_| NoiseError::DecryptionFailed)?;
                
            self.mix_hash(ciphertext);
            Ok(plaintext)
        } else {
            // No key yet, just update hash
            self.mix_hash(ciphertext);
            Ok(ciphertext.to_vec())
        }
    }
    
    /// Write handshake message for XX pattern
    pub fn write_message(&mut self) -> Result<Vec<u8>, NoiseError> {
        debug_noise_full_println!("Writing handshake message, role: {:?}, step: {}", self.role, self.step);
        
        match (self.role, self.step) {
            // Initiator step 1: -> e
            (NoiseRole::Initiator, 0) => {
                let ephemeral = StaticSecret::random();
                let ephemeral_pub = PublicKey::from(&ephemeral);
                
                self.mix_hash(ephemeral_pub.as_bytes());
                self.local_ephemeral = Some(ephemeral);
                
                self.step += 1;
                debug_noise_println!("Initiator step 1: Sent ephemeral key");
                Ok(ephemeral_pub.as_bytes().to_vec())
            }
            
            // Responder step 2: <- e, ee, s, es
            (NoiseRole::Responder, 1) => {
                let ephemeral = StaticSecret::random();
                let ephemeral_pub = PublicKey::from(&ephemeral);
                
                self.mix_hash(ephemeral_pub.as_bytes());
                
                // Store ephemeral key first (we'll need it later)
                self.local_ephemeral = Some(ephemeral);
                
                // ee - ephemeral-ephemeral DH
                if let (Some(local_eph), Some(remote_eph)) = (&self.local_ephemeral, &self.remote_ephemeral) {
                    let shared_secret = local_eph.diffie_hellman(remote_eph);
                    self.mix_key(shared_secret.as_bytes());
                }
                
                let mut message = ephemeral_pub.as_bytes().to_vec();
                
                // s
                let static_pub = PublicKey::from(&self.local_static);
                let encrypted_static = self.encrypt(static_pub.as_bytes())?;
                message.extend_from_slice(&encrypted_static);
                
                // es
                if let Some(remote_eph) = &self.remote_ephemeral {
                    let es = self.local_static.diffie_hellman(remote_eph);
                    self.mix_key(es.as_bytes());
                }
                
                self.step += 1;
                debug_noise_println!("Responder step 2: Sent ephemeral key + encrypted static key");
                Ok(message)
            }
            
            // Initiator step 3: -> s, se
            (NoiseRole::Initiator, 2) => {
                // s
                let static_pub = PublicKey::from(&self.local_static);
                let encrypted_static = self.encrypt(static_pub.as_bytes())?;
                
                // se
                if let Some(remote_static) = &self.remote_static {
                    if let Some(local_eph) = &self.local_ephemeral {
                        let se = local_eph.diffie_hellman(remote_static);
                        self.mix_key(se.as_bytes());
                    }
                }
                
                self.step += 1;
                debug_noise_println!("Initiator step 3: Sent encrypted static key");
                Ok(encrypted_static)
            }
            
            _ => Err(NoiseError::InvalidHandshakeState)
        }
    }
    
    /// Read handshake message for XX pattern
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        debug_noise_full_println!("Reading handshake message, role: {:?}, step: {}", self.role, self.step);
        
        match (self.role, self.step) {
            // Responder step 1: -> e
            (NoiseRole::Responder, 0) => {
                if message.len() != 32 {
                    return Err(NoiseError::InvalidMessage);
                }
                
                self.remote_ephemeral = Some(Self::validate_public_key(message)?);
                self.mix_hash(message);
                
                self.step += 1;
                debug_noise_println!("Responder step 1: Received ephemeral key");
                Ok(Vec::new())
            }
            
            // Initiator step 2: <- e, ee, s, es
            (NoiseRole::Initiator, 1) => {
                if message.len() < 32 {
                    return Err(NoiseError::InvalidMessage);
                }
                
                // e
                let remote_ephemeral = Self::validate_public_key(&message[..32])?;
                self.mix_hash(&message[..32]);
                self.remote_ephemeral = Some(remote_ephemeral);
                
                // s - decrypt static key first
                let encrypted_static = &message[32..];
                let static_bytes = self.decrypt(encrypted_static)?;
                let remote_static_key = Self::validate_public_key(&static_bytes)?;
                self.remote_static = Some(remote_static_key);
                
                // ee and es - clone the ephemeral secret to avoid borrow conflicts
                if let Some(local_eph) = self.local_ephemeral.clone() {
                    // ee = DH(local_ephemeral, remote_ephemeral)
                    let ee = local_eph.diffie_hellman(&remote_ephemeral);
                    self.mix_key(ee.as_bytes());
                    
                    // es = DH(local_ephemeral, remote_static) - clone again since diffie_hellman consumes it
                    let local_eph_clone = self.local_ephemeral.as_ref().unwrap().clone();
                    let es = local_eph_clone.diffie_hellman(&remote_static_key);
                    self.mix_key(es.as_bytes());
                }
                
                self.step += 1;
                debug_noise_println!("Initiator step 2: Received ephemeral key + encrypted static key");
                Ok(Vec::new())
            }
            
            // Responder step 3: -> s, se
            (NoiseRole::Responder, 2) => {
                // s
                let static_bytes = self.decrypt(message)?;
                self.remote_static = Some(Self::validate_public_key(&static_bytes)?);
                
                // se
                if let Some(remote_eph) = &self.remote_ephemeral {
                    let se = self.local_static.diffie_hellman(remote_eph);
                    self.mix_key(se.as_bytes());
                }
                
                self.step += 1;
                debug_noise_println!("Responder step 3: Received encrypted static key");
                Ok(Vec::new())
            }
            
            _ => Err(NoiseError::InvalidHandshakeState)
        }
    }
    
    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.step >= 3
    }
    
    /// Split into encryption and decryption ciphers
    pub fn split(self) -> Result<(NoiseCipherState, NoiseCipherState), NoiseError> {
        if !self.is_complete() {
            return Err(NoiseError::InvalidHandshakeState);
        }
        
        let hkdf = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hkdf.expand(&[], &mut output).unwrap();
        
        let k1 = output[..32].try_into().unwrap();
        let k2 = output[32..].try_into().unwrap();
        
        let (send_key, recv_key) = match self.role {
            NoiseRole::Initiator => (k1, k2),
            NoiseRole::Responder => (k2, k1),
        };
        
        Ok((
            NoiseCipherState::new(send_key),
            NoiseCipherState::new(recv_key),
        ))
    }
    
    /// Get the remote static public key after successful handshake
    pub fn get_remote_static(&self) -> Option<PublicKey> {
        self.remote_static
    }
}

/// Cipher state for post-handshake encryption/decryption
#[derive(Debug)]
pub struct NoiseCipherState {
    key: [u8; 32],
    nonce: u64,
}

impl NoiseCipherState {
    fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        
        // Convert nonce to little-endian bytes and pad to 12 bytes
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;
        
        self.nonce += 1;
        Ok(ciphertext)
    }
    
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        
        // Convert nonce to little-endian bytes and pad to 12 bytes
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;
        
        self.nonce += 1;
        Ok(plaintext)
    }
}

/// A complete Noise session with timeout and message counting
pub struct NoiseSession {
    peer_id: String,
    role: NoiseRole,
    handshake_state: Option<NoiseHandshakeState>,
    send_cipher: Option<NoiseCipherState>,
    recv_cipher: Option<NoiseCipherState>,
    remote_static_key: Option<PublicKey>,
    last_activity: Instant,
    message_count: u64,
    established: bool,
}

impl NoiseSession {
    pub fn new(peer_id: String, role: NoiseRole, local_static: StaticSecret) -> Self {
        let handshake_state = NoiseHandshakeState::new(role, HandshakePattern::XX, local_static);
        
        Self {
            peer_id,
            role,
            handshake_state: Some(handshake_state),
            send_cipher: None,
            recv_cipher: None,
            remote_static_key: None,
            last_activity: Instant::now(),
            message_count: 0,
            established: false,
        }
    }
    
    /// Start handshake (for initiator)
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, NoiseError> {
        if let Some(ref mut hs) = self.handshake_state {
            let message = hs.write_message()?;
            self.last_activity = Instant::now();
            debug_noise_println!("Started handshake with peer {}", self.peer_id);
            Ok(message)
        } else {
            Err(NoiseError::InvalidHandshakeState)
        }
    }
    
    /// Process handshake message
    pub fn process_handshake_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, NoiseError> {
        if let Some(ref mut hs) = self.handshake_state {
            hs.read_message(message)?;
            self.last_activity = Instant::now();
            
            let response = if !hs.is_complete() && self.role == NoiseRole::Responder && hs.step == 2 {
                Some(hs.write_message()?)
            } else {
                None
            };
            
            let is_complete = hs.is_complete();
            if is_complete {
                debug_noise_println!("Handshake completed with peer {}", self.peer_id);
                // Take ownership of handshake state to call split()
                let hs = self.handshake_state.take().unwrap();
                let remote_static = hs.get_remote_static();
                let (send_cipher, recv_cipher) = hs.split()?;
                
                self.remote_static_key = remote_static;
                self.send_cipher = Some(send_cipher);
                self.recv_cipher = Some(recv_cipher);
                self.established = true;
            }
            
            Ok(response)
        } else {
            Err(NoiseError::InvalidHandshakeState)
        }
    }
    
    /// Encrypt application data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(ref mut cipher) = self.send_cipher {
            let ciphertext = cipher.encrypt(plaintext)?;
            self.last_activity = Instant::now();
            self.message_count += 1;
            
            debug_noise_full_println!("Encrypted message for peer {} (count: {})", self.peer_id, self.message_count);
            Ok(ciphertext)
        } else {
            Err(NoiseError::SessionNotEstablished)
        }
    }
    
    /// Decrypt application data
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(ref mut cipher) = self.recv_cipher {
            let plaintext = cipher.decrypt(ciphertext)?;
            self.last_activity = Instant::now();
            
            debug_noise_full_println!("Decrypted message from peer {}", self.peer_id);
            Ok(plaintext)
        } else {
            Err(NoiseError::SessionNotEstablished)
        }
    }
    
    /// Check if session is established
    pub fn is_established(&self) -> bool {
        self.established
    }
    
    /// Check if session needs rekeying (30 minutes or 900k messages)
    pub fn needs_rekeying(&self) -> bool {
        let time_expired = self.last_activity.elapsed() > Duration::from_secs(30 * 60);
        let message_limit = self.message_count >= 900_000;
        time_expired || message_limit
    }
    
    /// Get remote static public key
    pub fn get_remote_static_key(&self) -> Option<PublicKey> {
        self.remote_static_key
    }
    
    /// Get fingerprint of remote static key
    pub fn get_remote_fingerprint(&self) -> Option<String> {
        self.remote_static_key.map(|key| {
            let hash = Sha256::digest(key.as_bytes());
            hex::encode(&hash[..16])
        })
    }
}

/// Session manager for handling multiple Noise sessions
pub struct NoiseSessionManager {
    local_static: StaticSecret,
    sessions: Arc<RwLock<HashMap<String, NoiseSession>>>,
    rate_limits: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl NoiseSessionManager {
    pub fn new() -> Self {
        let local_static = StaticSecret::random();
        
        Self {
            local_static,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Check rate limits (max 5 handshakes per minute per peer)
    fn check_rate_limit(&self, peer_id: &str) -> bool {
        let mut limits = self.rate_limits.lock().unwrap();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);
        
        let peer_attempts = limits.entry(peer_id.to_string()).or_default();
        peer_attempts.retain(|&time| time > one_minute_ago);
        
        if peer_attempts.len() >= 5 {
            debug_noise_println!("Rate limit exceeded for peer {}", peer_id);
            return false;
        }
        
        peer_attempts.push(now);
        true
    }
    
    /// Create a new session for a peer
    pub fn create_session(&self, peer_id: &str, role: NoiseRole) -> Result<(), NoiseError> {
        if !self.check_rate_limit(peer_id) {
            return Err(NoiseError::RateLimitExceeded);
        }
        
        let session = NoiseSession::new(peer_id.to_string(), role, self.local_static.clone());
        
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(peer_id.to_string(), session);
        
        debug_noise_println!("Created new Noise session for peer {} (role: {:?})", peer_id, role);
        Ok(())
    }
    
    /// Get a session for a peer (mutable access)
    pub fn with_session<F, R>(&self, peer_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut NoiseSession) -> R,
    {
        let mut sessions = self.sessions.write().unwrap();
        sessions.get_mut(peer_id).map(f)
    }
    
    /// Remove a session
    pub fn remove_session(&self, peer_id: &str) -> bool {
        let mut sessions = self.sessions.write().unwrap();
        let removed = sessions.remove(peer_id).is_some();
        
        if removed {
            debug_noise_println!("Removed Noise session for peer {}", peer_id);
        }
        
        removed
    }
    
    /// Get all sessions that need rekeying
    pub fn get_sessions_needing_rekey(&self) -> Vec<String> {
        let sessions = self.sessions.read().unwrap();
        sessions.iter()
            .filter(|(_, session)| session.needs_rekeying())
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }
    
    /// Get our local static public key
    pub fn get_local_static_public(&self) -> PublicKey {
        PublicKey::from(&self.local_static)
    }
    
    /// Get fingerprint of our local static key
    pub fn get_local_fingerprint(&self) -> String {
        let public_key = self.get_local_static_public();
        let hash = Sha256::digest(public_key.as_bytes());
        hex::encode(&hash[..16])
    }
    
    /// Check if a session exists for a peer
    pub fn has_session(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.read().unwrap();
        sessions.contains_key(peer_id)
    }
    
    /// Check if a session is established for a peer
    pub fn is_established(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.read().unwrap();
        sessions.get(peer_id).map(|s| s.is_established()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        let alice_static = StaticSecret::random();
        let bob_static = StaticSecret::random();
        
        let mut alice = NoiseHandshakeState::new(NoiseRole::Initiator, HandshakePattern::XX, alice_static);
        let mut bob = NoiseHandshakeState::new(NoiseRole::Responder, HandshakePattern::XX, bob_static);
        
        // Step 1: Alice -> Bob
        let msg1 = alice.write_message().unwrap();
        bob.read_message(&msg1).unwrap();
        
        // Step 2: Bob -> Alice
        let msg2 = bob.write_message().unwrap();
        alice.read_message(&msg2).unwrap();
        
        // Step 3: Alice -> Bob
        let msg3 = alice.write_message().unwrap();
        bob.read_message(&msg3).unwrap();
        
        assert!(alice.is_complete());
        assert!(bob.is_complete());
        
        // Split and test encryption
        let (mut alice_send, mut alice_recv) = alice.split().unwrap();
        let (mut bob_send, mut bob_recv) = bob.split().unwrap();
        
        let plaintext = b"Hello from Alice!";
        let ciphertext = alice_send.encrypt(plaintext).unwrap();
        let decrypted = bob_recv.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
} 