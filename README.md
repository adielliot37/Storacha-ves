# Storacha VES (Verifiable Encrypted Storage)

This project implements a verifiable encrypted storage system using Storacha's MCP REST API. It provides client-side encryption, decentralized storage, integrity verification, and decryption with comprehensive key management and automatic backup systems.

### Blog: [Storacha VES: Verifiable Encrypted Storage Made Simple](https://medium.com/@akashjana663/storacha-ves-verifiable-encrypted-storage-made-simple-7f165f792ae6)

## Features

### Core Functionality
- AES-256-GCM encryption in the browser with WebCrypto API
- Password-based key derivation using PBKDF2 (100,000 iterations, SHA-256)
- Encrypted key export/import with password protection
- Automatic encrypted key backup generation
- Chunked file upload to Storacha via MCP REST API (4MB chunks)
- File size validation (10MB limit)

### Cryptographic Operations
- SHA-256 Merkle tree construction for integrity verification
- Merkle proof verification without decryption
- Challenge-response integrity verification system
- Client-side decryption and file reconstruction

### Key Management
- Smart key workflow: checks for existing keys before generating new ones
- Three key sources: generated, imported from file, or derived from password
- Automatic encrypted backup download for generated keys
- Password strength validation for derived keys
- Session-based key storage (lost on refresh unless backed up)

### Data Persistence
- Local manifest history storage (last 10 files) in browser localStorage
- Manifest recovery and reloading functionality
- Progress tracking with time estimates for upload operations

## Project Structure
storacha-ves/  
├── server/                  
│   ├── .env                 
│   ├── package.json  
│   └── index.js              
├── web/                     
│   ├── package.json  
│   ├── index.html  
│   ├── src/  
│   │   ├── main.jsx  
│   │   ├── App.jsx          
│   │   ├── styles.css  
│   │   ├── components/  
│   │   │   └── LogPanel.jsx  
│   │   └── utils/  
│   │       ├── api.js        
│   │       ├── bytes.js      # hex/ArrayBuffer conversion helpers  
│   │       ├── crypto.js     # AES and SHA-256 helpers  
│   │       └── merkle.js     # Merkle tree and proof verification  
└── README.md

<img width="1207" height="593" alt="Screenshot 2025-08-12 at 2 33 57 PM" src="https://github.com/user-attachments/assets/06c70f2d-003a-4c8c-a81b-e6d5192d3c5c" />

## Technical Flow

### 1. Key Management and Encryption Setup
1. Before encryption, the system checks for existing keys in memory.
2. If no key exists, the user is prompted to:
   - Generate a new AES-256-GCM key (with automatic encrypted backup)
   - Import an existing encrypted key file
   - Derive a key from password using PBKDF2
3. For generated keys, an automatic encrypted backup is created and downloaded.
4. For password-derived keys, password strength is validated (minimum 8 characters, mixed case, numbers, symbols).

### 2. Encryption and Upload
1. The user selects a file (validated against 10MB limit).
2. The file is split into 4MB chunks.
3. For each chunk:
   - Generate a random 12-byte IV.
   - Encrypt the chunk with AES-256-GCM using the established key and IV.
   - Compute SHA-256 hash of the ciphertext.
   - Send the ciphertext to the server with `POST /upload-chunk`.
4. The server calls MCP REST `tools/call` with method `upload` and receives:
   - `payload.files[name]['/']` → File CID (used in `chunkCIDs`)
   - `payload.root['/']` → Root CID (not used in retrieval)
5. The client collects all chunk CIDs and SHA-256 hashes to build a Merkle tree and compute the Merkle root.
6. A manifest JSON is created and uploaded via `POST /upload-manifest`.
7. The manifest is stored in local browser history (last 10 manifests) for recovery.

### 3. Verification (Challenge)
1. A random chunk index is selected from the manifest.
2. The chunk is fetched from IPFS using its CID.
3. SHA-256 hash is computed and compared against the manifest's stored hash using a Merkle proof.
4. If the proof matches the Merkle root, integrity is verified without decryption.

### 4. Decryption
1. All chunk CIDs are fetched from IPFS in sequence.
2. Each chunk is decrypted with AES-256-GCM using the IV from the manifest and the AES key.
3. The decrypted chunks are concatenated into the original file for download.
4. Progress tracking shows completion percentage and estimated time remaining.

## Key Storage and Security

### Key Management Security
- AES keys are generated using WebCrypto API and stored only in browser memory during the session.
- Keys are never uploaded to the server or stored on Storacha.
- Automatic encrypted key backups use PBKDF2 (100,000 iterations, SHA-256) for password protection.
- Exported key files contain: encrypted key data, salt, IV, timestamp, and version information.

### Cryptographic Security
- Without the AES key, encrypted chunks cannot be decrypted even if their CIDs and IVs are known.
- Merkle tree verification ensures data integrity without requiring decryption.
- Each chunk uses a unique random IV, preventing replay attacks.
- Password-derived keys use cryptographically secure salt generation.

## How to Run
### Backend
```bash
cd server
npm install
cp .env.example .env  # fill in MCP_REST_URL, DELEGATION, CLIENT_ORIGIN
node index.js
```
### Frontend
```bash
cd web
npm install
npm run dev
```
## Example Manifest
```bash
{
  "version": 3,
  "fileName": "example.pdf",
  "totalSize": 219581,
  "chunkSize": 4194304,
  "leaves": [
    "c6dbb041110882b6fbe1360a547fa66fec351549114b7aac63fe82416fb6df50"
  ],
  "merkleRootSHA256": "c6dbb041110882b6fbe1360a547fa66fec351549114b7aac63fe82416fb6df50",
  "chunkCIDs": [
    "bafkreigg3oyeceiiqk3pxyjwbjkh7jtp5q2rksirjn5kyy76qjaw7nw7ka"
  ],
  "ivs": [
    "5bef01fd20d3e9ba0eea3378"
  ],
  "algo": {
    "hash": "sha256",
    "enc": "aes-256-gcm"
  }
}
```
