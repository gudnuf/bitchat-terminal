use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

// Import our Noise implementation
use crate::noise_encryption::{NoiseSessionManager, NoiseRole, NoiseError};

// Add debug macros for encryption logging
macro_rules! debug_encryption_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::DEBUG_LEVEL as u8 >= crate::DebugLevel::Basic as u8 {
                println!("[ENCRYPTION] {}", format!($($arg)*));
            }
        }
    };
}

#[derive(Debug)]
pub enum EncryptionError {
    NoSharedSecret,
    InvalidPublicKey,
    EncryptionFailed,
    DecryptionFailed,
    #[allow(dead_code)]
    SignatureVerificationFailed,
    NoiseProtocolError(NoiseError),
}

impl From<NoiseError> for EncryptionError {
    fn from(err: NoiseError) -> Self {
        EncryptionError::NoiseProtocolError(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionType {
    Legacy,  // Original X25519 + AES-GCM
    Noise,   // Noise Protocol XX pattern
}

pub struct EncryptionService {
    // Legacy encryption components
    private_key: StaticSecret,
    public_key: PublicKey,
    
    // Signing keys for authentication
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    
    // Persistent identity for favorites (separate from ephemeral keys)
    _identity_key: SigningKey,  // Reserved for future features
    identity_public: VerifyingKey,
    
    // Storage for peer keys - wrapped in Arc<RwLock> for thread safety
    peer_public_keys: Arc<RwLock<HashMap<String, PublicKey>>>,
    peer_signing_keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
    peer_identity_keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
    shared_secrets: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    
    // Noise Protocol components
    noise_manager: NoiseSessionManager,
    
    // Track which encryption type each peer supports
    peer_encryption_types: Arc<RwLock<HashMap<String, EncryptionType>>>,
    
    // Flag to prefer Noise Protocol for new connections
    prefer_noise: bool,
}

impl EncryptionService {
    pub fn new() -> Self {
        // Generate ephemeral key pairs for this session
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        // Generate persistent identity key for this session
        let identity_key = SigningKey::generate(&mut OsRng);
        let identity_public = identity_key.verifying_key();
        
        Self {
            private_key,
            public_key,
            signing_key,
            verifying_key,
            _identity_key: identity_key,
            identity_public,
            peer_public_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_signing_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_identity_keys: Arc::new(RwLock::new(HashMap::new())),
            shared_secrets: Arc::new(RwLock::new(HashMap::new())),
            noise_manager: NoiseSessionManager::new(),
            peer_encryption_types: Arc::new(RwLock::new(HashMap::new())),
            prefer_noise: true, // Prefer Noise Protocol for new connections
        }
    }
    
    /// Create combined public key data for exchange (128 bytes total)
    /// Format: 32 bytes legacy encryption + 32 bytes legacy signing + 32 bytes identity + 32 bytes noise static
    pub fn get_combined_public_key_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        
        // Legacy keys (96 bytes - compatible with old format)
        data.extend_from_slice(self.public_key.as_bytes());         // 32 bytes - ephemeral encryption key
        data.extend_from_slice(&self.verifying_key.to_bytes());     // 32 bytes - ephemeral signing key
        data.extend_from_slice(&self.identity_public.to_bytes());   // 32 bytes - persistent identity key
        
        // Noise Protocol static key (32 bytes - new!)
        let noise_static_public = self.noise_manager.get_local_static_public();
        data.extend_from_slice(noise_static_public.as_bytes());     // 32 bytes - Noise static key
        
        debug_encryption_println!("Created combined key data: {} bytes (includes Noise support)", data.len());
        data  // Total: 128 bytes
    }
    
    /// Create legacy 96-byte public key data for compatibility with existing bitchat apps
    pub fn get_legacy_public_key_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(96);
        
        // Legacy keys only (96 bytes - compatible with iOS/Android apps)
        data.extend_from_slice(self.public_key.as_bytes());         // 32 bytes - ephemeral encryption key
        data.extend_from_slice(&self.verifying_key.to_bytes());     // 32 bytes - ephemeral signing key
        data.extend_from_slice(&self.identity_public.to_bytes());   // 32 bytes - persistent identity key
        
        debug_encryption_println!("Created legacy key data: {} bytes (compatible mode)", data.len());
        data  // Total: 96 bytes
    }
    
    /// Add peer's combined public keys and detect supported encryption types
    pub fn add_peer_public_key(&self, peer_id: &str, public_key_data: &[u8]) -> Result<(), EncryptionError> {
        debug_encryption_println!("Adding public key for peer {}, data size: {} bytes", peer_id, public_key_data.len());
        
        let encryption_type = if public_key_data.len() == 128 {
            // New format with Noise support
            debug_encryption_println!("Peer {} supports Noise Protocol (128-byte key)", peer_id);
            
            // Extract all four keys
            let legacy_key_bytes: [u8; 32] = public_key_data[0..32]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            let signing_key_bytes: [u8; 32] = public_key_data[32..64]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            let identity_key_bytes: [u8; 32] = public_key_data[64..96]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            let _noise_static_bytes: [u8; 32] = public_key_data[96..128]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            
            // Store legacy keys for fallback compatibility
            self.store_legacy_keys(peer_id, &legacy_key_bytes, &signing_key_bytes, &identity_key_bytes)?;
            
            // Initiate Noise handshake if we prefer Noise
            if self.prefer_noise {
                debug_encryption_println!("Initiating Noise handshake with peer {}", peer_id);
                if let Err(e) = self.noise_manager.create_session(peer_id, NoiseRole::Initiator) {
                    debug_encryption_println!("Failed to create Noise session for {}: {:?}, falling back to legacy", peer_id, e);
                    EncryptionType::Legacy
                } else {
                    EncryptionType::Noise
                }
            } else {
                EncryptionType::Legacy
            }
        } else if public_key_data.len() == 96 {
            // Legacy format (original protocol)
            debug_encryption_println!("Peer {} uses legacy encryption (96-byte key)", peer_id);
            
            let legacy_key_bytes: [u8; 32] = public_key_data[0..32]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            let signing_key_bytes: [u8; 32] = public_key_data[32..64]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            let identity_key_bytes: [u8; 32] = public_key_data[64..96]
                .try_into()
                .map_err(|_| EncryptionError::InvalidPublicKey)?;
            
            self.store_legacy_keys(peer_id, &legacy_key_bytes, &signing_key_bytes, &identity_key_bytes)?;
            EncryptionType::Legacy
        } else {
            return Err(EncryptionError::InvalidPublicKey);
        };
        
        // Store the encryption type for this peer
        {
            let mut types = self.peer_encryption_types.write().unwrap();
            types.insert(peer_id.to_string(), encryption_type);
        }
        
        debug_encryption_println!("Peer {} configured for {:?} encryption", peer_id, encryption_type);
        Ok(())
    }
    
    /// Store legacy keys for a peer (extracted from combined key data)
    fn store_legacy_keys(&self, peer_id: &str, key_bytes: &[u8; 32], signing_bytes: &[u8; 32], identity_bytes: &[u8; 32]) -> Result<(), EncryptionError> {
        let public_key = PublicKey::from(*key_bytes);
        
        // Parse signing key - iOS keys will parse correctly
        let signing_key = VerifyingKey::from_bytes(signing_bytes)
            .map_err(|_| EncryptionError::InvalidPublicKey)?;
        
        // Parse identity key with Android compatibility fallback
        let identity_key = match VerifyingKey::from_bytes(identity_bytes) {
            Ok(key) => key,
            Err(_) => {
                // This is likely Android with the identity key bug
                debug_encryption_println!("Note: Peer {} appears to be Android (invalid identity key format)", peer_id);
                signing_key.clone()
            }
        };
        
        // Store all keys
        {
            let mut peer_keys = self.peer_public_keys.write().unwrap();
            peer_keys.insert(peer_id.to_string(), public_key);
        }
        {
            let mut signing_keys = self.peer_signing_keys.write().unwrap();
            signing_keys.insert(peer_id.to_string(), signing_key);
        }
        {
            let mut identity_keys = self.peer_identity_keys.write().unwrap();
            identity_keys.insert(peer_id.to_string(), identity_key);
        }
        
        // Generate shared secret for legacy encryption
        let shared_secret = self.private_key.diffie_hellman(&public_key);
        
        // Derive symmetric key using HKDF (matching Swift's implementation)
        let hkdf = Hkdf::<Sha256>::new(Some(b"bitchat-v1"), shared_secret.as_bytes());
        let mut symmetric_key = [0u8; 32];
        hkdf.expand(&[], &mut symmetric_key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Store shared secret for legacy fallback
        {
            let mut secrets = self.shared_secrets.write().unwrap();
            secrets.insert(peer_id.to_string(), symmetric_key);
        }
        
        Ok(())
    }
    
    /// Get what encryption type we're using for a peer
    pub fn get_peer_encryption_type(&self, peer_id: &str) -> Option<EncryptionType> {
        let types = self.peer_encryption_types.read().unwrap();
        types.get(peer_id).copied()
    }
    
    /// Try to initiate Noise handshake with a peer
    pub fn initiate_noise_handshake(&self, peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        // First check if peer supports Noise
        if let Some(EncryptionType::Noise) = self.get_peer_encryption_type(peer_id) {
            debug_encryption_println!("Starting Noise handshake with peer {}", peer_id);
            
            if !self.noise_manager.has_session(peer_id) {
                self.noise_manager.create_session(peer_id, NoiseRole::Initiator)?;
            }
            
            if let Some(handshake_msg) = self.noise_manager.with_session(peer_id, |session| {
                session.start_handshake()
            }) {
                return handshake_msg.map_err(EncryptionError::from);
            }
        }
        
        Err(EncryptionError::NoSharedSecret)
    }
    
    /// Process incoming Noise handshake message
    pub fn process_noise_handshake(&self, peer_id: &str, message: &[u8]) -> Result<Option<Vec<u8>>, EncryptionError> {
        debug_encryption_println!("Processing Noise handshake from peer {}", peer_id);
        
        // Create session if we don't have one (responder role)
        if !self.noise_manager.has_session(peer_id) {
            self.noise_manager.create_session(peer_id, NoiseRole::Responder)?;
            
            // Mark peer as supporting Noise
            let mut types = self.peer_encryption_types.write().unwrap();
            types.insert(peer_id.to_string(), EncryptionType::Noise);
        }
        
        if let Some(result) = self.noise_manager.with_session(peer_id, |session| {
            session.process_handshake_message(message)
        }) {
            let response = result.map_err(EncryptionError::from)?;
            
            if self.noise_manager.is_established(peer_id) {
                debug_encryption_println!("✓ Noise session established with peer {}", peer_id);
            }
            
            return Ok(response);
        }
        
        Err(EncryptionError::NoSharedSecret)
    }
    
    /// Encrypt data for a specific peer using the appropriate protocol
    pub fn encrypt(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        let encryption_type = self.get_peer_encryption_type(peer_id)
            .unwrap_or(EncryptionType::Legacy);
        
        match encryption_type {
            EncryptionType::Noise => {
                if self.noise_manager.is_established(peer_id) {
                    debug_encryption_println!("Encrypting with Noise Protocol for peer {}", peer_id);
                    
                    if let Some(result) = self.noise_manager.with_session(peer_id, |session| {
                        session.encrypt(data)
                    }) {
                        return result.map_err(EncryptionError::from);
                    } else {
                        debug_encryption_println!("Noise session not ready for {}, falling back to legacy", peer_id);
                        // Fall back to legacy encryption
                    }
                } else {
                    debug_encryption_println!("Noise session not established for {}, falling back to legacy", peer_id);
                    // Fall back to legacy encryption
                }
            }
            EncryptionType::Legacy => {
                debug_encryption_println!("Using legacy encryption for peer {}", peer_id);
            }
        }
        
        // Legacy encryption fallback
        self.encrypt_legacy(data, peer_id)
    }
    
    /// Decrypt data from a specific peer using the appropriate protocol
    pub fn decrypt(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        let encryption_type = self.get_peer_encryption_type(peer_id)
            .unwrap_or(EncryptionType::Legacy);
        
        match encryption_type {
            EncryptionType::Noise => {
                if self.noise_manager.is_established(peer_id) {
                    debug_encryption_println!("Decrypting with Noise Protocol from peer {}", peer_id);
                    
                    if let Some(result) = self.noise_manager.with_session(peer_id, |session| {
                        session.decrypt(data)
                    }) {
                        return result.map_err(EncryptionError::from);
                    } else {
                        debug_encryption_println!("Noise session not ready for {}, trying legacy", peer_id);
                        // Fall back to legacy decryption
                    }
                } else {
                    debug_encryption_println!("Noise session not established for {}, trying legacy", peer_id);
                    // Fall back to legacy decryption
                }
            }
            EncryptionType::Legacy => {
                debug_encryption_println!("Using legacy decryption for peer {}", peer_id);
            }
        }
        
        // Legacy decryption fallback
        self.decrypt_legacy(data, peer_id)
    }
    
    /// Legacy encryption implementation
    fn encrypt_legacy(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        let secrets = self.shared_secrets.read().unwrap();
        let symmetric_key = secrets.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let cipher = Aes256Gcm::new_from_slice(symmetric_key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Return combined format matching Swift (nonce + ciphertext + tag)
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Legacy decryption implementation
    fn decrypt_legacy(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {  // Minimum size for nonce
            return Err(EncryptionError::DecryptionFailed);
        }
        
        let secrets = self.shared_secrets.read().unwrap();
        let symmetric_key = secrets.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let cipher = Aes256Gcm::new_from_slice(symmetric_key)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    /// Get peer's persistent identity key for favorites
    pub fn get_peer_identity_key(&self, peer_id: &str) -> Option<Vec<u8>> {
        let identity_keys = self.peer_identity_keys.read().unwrap();
        identity_keys.get(peer_id).map(|key| key.to_bytes().to_vec())
    }
    
    /// Calculate SHA256 fingerprint of a peer's identity key (first 16 bytes as hex)
    pub fn get_peer_fingerprint(&self, peer_id: &str) -> Option<String> {
        // Try Noise fingerprint first if available
        if let Some(EncryptionType::Noise) = self.get_peer_encryption_type(peer_id) {
            if let Some(fingerprint) = self.noise_manager.with_session(peer_id, |session| {
                session.get_remote_fingerprint()
            }).flatten() {
                debug_encryption_println!("Using Noise fingerprint for peer {}", peer_id);
                return Some(fingerprint);
            }
        }
        
        // Fall back to legacy fingerprint
        self.get_peer_identity_key(peer_id).map(|key_bytes| {
            use sha2::Digest;
            let hash = Sha256::digest(&key_bytes);
            // Take first 16 bytes and convert to lowercase hex
            hash.iter()
                .take(16)
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        })
    }
    
    /// Sign data using our signing key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }
    
    /// Verify signature from a peer
    #[allow(dead_code)]
    pub fn verify(&self, signature: &[u8], data: &[u8], peer_id: &str) -> Result<bool, EncryptionError> {
        let signing_keys = self.peer_signing_keys.read().unwrap();
        let verifying_key = signing_keys.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let signature_bytes: [u8; 64] = signature.try_into()
            .map_err(|_| EncryptionError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes);
        
        Ok(verifying_key.verify_strict(data, &signature).is_ok())
    }
    
    /// Derive channel key from password (matching Swift's PBKDF2 implementation)
    pub fn derive_channel_key(password: &str, channel_name: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            channel_name.as_bytes(),  // Use channel name as salt
            100_000,                  // iterations matching Swift
            &mut key,
        );
        key
    }
    
    /// Encrypt data with a channel key (for password-protected channels)
    pub fn encrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Return combined format (nonce + ciphertext + tag)
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data with a channel key
    pub fn decrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::DecryptionFailed);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    /// Check if we have a peer's encryption key (either type)
    pub fn has_peer_key(&self, peer_id: &str) -> bool {
        // Check Noise session first
        if self.noise_manager.is_established(peer_id) {
            return true;
        }
        
        // Check legacy shared secrets
        let shared_secrets = self.shared_secrets.read().unwrap();
        shared_secrets.contains_key(peer_id)
    }
    
    /// Encrypt data specifically for a peer (used for ACKs)
    pub fn encrypt_for_peer(&self, peer_id: &str, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // This is the same as encrypt() but makes the intent clearer
        self.encrypt(data, peer_id)
    }
    
    /// Get encryption status for all peers (for debugging)
    pub fn get_encryption_status(&self) -> Vec<(String, EncryptionType, bool)> {
        let types = self.peer_encryption_types.read().unwrap();
        types.iter().map(|(peer_id, &enc_type)| {
            let has_session = match enc_type {
                EncryptionType::Noise => self.noise_manager.is_established(peer_id),
                EncryptionType::Legacy => {
                    let secrets = self.shared_secrets.read().unwrap();
                    secrets.contains_key(peer_id)
                }
            };
            (peer_id.clone(), enc_type, has_session)
        }).collect()
    }
    
    /// Force cleanup of expired Noise sessions
    pub fn cleanup_noise_sessions(&self) {
        let sessions_needing_rekey = self.noise_manager.get_sessions_needing_rekey();
        for peer_id in sessions_needing_rekey {
            debug_encryption_println!("Cleaning up expired Noise session for peer {}", peer_id);
            self.noise_manager.remove_session(&peer_id);
            
            // Mark peer to use legacy encryption
            let mut types = self.peer_encryption_types.write().unwrap();
            types.insert(peer_id, EncryptionType::Legacy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = EncryptionService::new();
        let bob = EncryptionService::new();
        
        // Exchange public keys
        let alice_keys = alice.get_combined_public_key_data();
        let bob_keys = bob.get_combined_public_key_data();
        
        assert_eq!(alice_keys.len(), 128);
        assert_eq!(bob_keys.len(), 128);
        
        // Add each other's keys
        alice.add_peer_public_key("bob", &bob_keys).unwrap();
        bob.add_peer_public_key("alice", &alice_keys).unwrap();
        
        // Test encryption/decryption
        let message = b"Hello, Bob!";
        let encrypted = alice.encrypt(message, "bob").unwrap();
        let decrypted = bob.decrypt(&encrypted, "alice").unwrap();
        
        assert_eq!(message, &decrypted[..]);
    }
    
    #[test]
    fn test_legacy_key_exchange() {
        let alice = EncryptionService::new();
        let bob = EncryptionService::new();
        
        // Use legacy 96-byte key format
        let alice_keys = alice.get_legacy_public_key_data();
        let bob_keys = bob.get_legacy_public_key_data();
        
        assert_eq!(alice_keys.len(), 96);
        assert_eq!(bob_keys.len(), 96);
        
        // Add each other's keys - should use legacy encryption
        alice.add_peer_public_key("bob", &bob_keys).unwrap();
        bob.add_peer_public_key("alice", &alice_keys).unwrap();
        
        // Verify both peers are using legacy encryption
        assert_eq!(alice.get_peer_encryption_type("bob"), Some(EncryptionType::Legacy));
        assert_eq!(bob.get_peer_encryption_type("alice"), Some(EncryptionType::Legacy));
        
        // Test encryption/decryption with legacy protocol
        let message = b"Hello from legacy protocol!";
        let encrypted = alice.encrypt(message, "bob").unwrap();
        let decrypted = bob.decrypt(&encrypted, "alice").unwrap();
        
        assert_eq!(message, &decrypted[..]);
    }
    
    #[test]
    fn test_mixed_key_exchange() {
        let alice = EncryptionService::new();
        let bob = EncryptionService::new();
        
        // Alice sends legacy 96-byte key, Bob sends 128-byte key with Noise support
        let alice_keys = alice.get_legacy_public_key_data();
        let bob_keys = bob.get_combined_public_key_data();
        
        assert_eq!(alice_keys.len(), 96);
        assert_eq!(bob_keys.len(), 128);
        
        // Add each other's keys
        alice.add_peer_public_key("bob", &bob_keys).unwrap();
        bob.add_peer_public_key("alice", &alice_keys).unwrap();
        
        // Alice should see Bob as supporting Noise (128 bytes)
        // Bob should see Alice as legacy (96 bytes)
        assert_eq!(alice.get_peer_encryption_type("bob"), Some(EncryptionType::Noise));
        assert_eq!(bob.get_peer_encryption_type("alice"), Some(EncryptionType::Legacy));
        
        // Both should fall back to legacy encryption for compatibility
        let message = b"Cross-protocol message!";
        let encrypted = alice.encrypt(message, "bob").unwrap();
        let decrypted = bob.decrypt(&encrypted, "alice").unwrap();
        
        assert_eq!(message, &decrypted[..]);
    }
    
    #[test]
    fn test_channel_key_derivation() {
        let key1 = EncryptionService::derive_channel_key("password123", "#general");
        let key2 = EncryptionService::derive_channel_key("password123", "#general");
        let key3 = EncryptionService::derive_channel_key("different", "#general");
        
        assert_eq!(key1, key2);  // Same password + channel = same key
        assert_ne!(key1, key3);  // Different password = different key
    }
}