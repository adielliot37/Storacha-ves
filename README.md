# Storacha VES (Verifiable Encrypted Storage)

This project implements a verifiable encrypted storage system using Storacha’s MCP REST API. It provides client-side encryption, decentralized storage, integrity verification, and decryption using a locally-held AES key.

## Features
- AES-256-GCM encryption in the browser
- Chunked file upload to Storacha via MCP REST API
- Manifest file containing Merkle root, IVs, and chunk CIDs
- Merkle proof verification without decryption
- Client-side decryption and file reconstruction

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

## Technical Flow

### 1. Encryption and Upload
1. The user selects a file in the browser.
2. The app generates an AES-256-GCM key using WebCrypto and stores it only in memory (React state).
3. The file is split into 4MB chunks.
4. For each chunk:
   - Generate a random 12-byte IV.
   - Encrypt the chunk with AES-256-GCM using the key and IV.
   - Compute SHA-256 hash of the ciphertext.
   - Send the ciphertext to the server with `POST /upload-chunk`.
5. The server calls MCP REST `tools/call` with method `upload` and receives:
   - `payload.files[name]['/']` → File CID (used in `chunkCIDs`)
   - `payload.root['/']` → Root CID (not used in retrieval)
6. The client collects all chunk CIDs and SHA-256 hashes to build a Merkle tree and compute the Merkle root.
7. A manifest JSON is created containing:
   - version
   - original filename
   - total file size
   - chunk size
   - `leaves`: array of ciphertext SHA-256 hashes
   - `merkleRootSHA256`
   - `chunkCIDs`: CIDs for each encrypted chunk
   - `ivs`: initialization vectors for each chunk
   - encryption and hash algorithm info
8. The manifest is uploaded via `POST /upload-manifest` and its CID is stored.

### 2. Verification (Challenge)
1. On “Challenge”, a random chunk index is selected.
2. The chunk is fetched from IPFS using its CID.
3. SHA-256 hash is computed and compared against the manifest’s stored hash using a Merkle proof.
4. If the proof matches the Merkle root, integrity is verified without decryption.

### 3. Decryption
1. On “Decrypt”, all chunk CIDs are fetched from IPFS.
2. Each chunk is decrypted with AES-256-GCM using the IV from the manifest and the AES key in memory.
3. The decrypted chunks are concatenated into the original file for download.

## Key Storage and Security
- The AES key is generated and stored only in browser memory during the session.
- It is never uploaded to the server or stored on Storacha.
- Without the AES key, encrypted chunks cannot be decrypted even if their CIDs and IVs are known.

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
