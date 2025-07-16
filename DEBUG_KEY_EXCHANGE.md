# Debugging Key Exchange in bitchat-terminal

## Overview

The bitchat-terminal now sends 96-byte key exchanges for compatibility with existing iOS/Android bitchat apps, while still supporting 128-byte exchanges for peers that support the Noise Protocol.

## Key Exchange Flow

1. **bitchat-terminal** sends a 96-byte key exchange containing:
   - 32 bytes: X25519 ephemeral encryption key
   - 32 bytes: Ed25519 ephemeral signing key  
   - 32 bytes: Ed25519 persistent identity key

2. **iOS/Android app** receives the keys and responds with its own 96-byte key exchange

3. Both sides derive a shared secret using X25519 Diffie-Hellman

4. The shared secret is used with HKDF to derive AES-256-GCM encryption keys

## Debugging Commands

### Enable Debug Logging

```bash
# Basic debug logging (recommended)
DEBUG_LEVEL=1 cargo run

# Full debug logging (very verbose)
DEBUG_LEVEL=2 cargo run
```

### New Commands

- `/keys` - Show encryption status for all discovered peers
- `/forcekey <nickname>` - Force a new key exchange with a specific peer

### What to Look For

1. **Bluetooth Traffic**
   ```
   [BLUETOOTH TX] Sending key exchange packet (102 bytes)
   [BLUETOOTH TX] Key exchange raw data: 0c020000...
   [BLUETOOTH RX] Received notification (102 bytes)
   [BLUETOOTH RX] Raw hex: 0c020000...
   ```

2. **Key Exchange Processing**
   ```
   [<-- RECV] Key exchange from abcd1234 (key: 96 bytes)
   [ENCRYPTION] Adding public key for peer abcd1234, data size: 96 bytes
   [ENCRYPTION] Peer abcd1234 uses legacy encryption (96-byte key)
   [+] Successfully added encryption keys for peer abcd1234
   ```

3. **Encryption Status**
   Use `/keys` to see:
   ```
   Encryption status:
   ✓ alice (abcd1234)
     Type: Legacy, Established: true
     Fingerprint: a1b2c3d4e5f67890
   ✗ bob (efgh5678)
   ```

## Common Issues

### No Key Exchange Received

If you see announces but no key exchanges:
- The iOS/Android app might not be sending key exchanges automatically
- Try sending a message from the iOS/Android app to trigger key exchange
- Use `/forcekey <nickname>` to manually trigger

### Key Exchange Fails

If key exchange is received but encryption fails:
- Check the key size in debug logs (should be 96 bytes)
- Verify the packet structure matches expected format
- Look for parsing errors in the logs

### Testing Encryption

1. After successful key exchange (✓ in `/keys`), try:
   ```
   /m alice Hello, this is encrypted!
   ```

2. Check debug logs for:
   ```
   [ENCRYPTION] Using legacy encryption for peer abcd1234
   ```

## Protocol Details

The bitchat packet format:
```
Offset  Size  Description
0       1     Version (0x0C)
1       1     Message Type (0x02 for KeyExchange)
2       1     TTL
3       1     Reserved
4       4     Sender ID
8       4     Fragment Info (zeros for non-fragmented)
12      2     Payload length
14      N     Payload (96 bytes for key exchange)
14+N    64    Signature (optional)
```

## Interoperability

- bitchat-terminal now sends 96-byte keys (legacy format)
- It can receive both 96-byte (legacy) and 128-byte (Noise) keys
- Noise Protocol is only used if both peers support it
- Legacy X25519 + AES-GCM is used for compatibility 