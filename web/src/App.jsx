import React, { useState } from 'react'
import LogPanel from './components/LogPanel.jsx'
import { genAESKey, aesGcmEncrypt, aesGcmDecrypt, sha256 } from './utils/crypto.js'
import { buildSha256Tree, merkleProofFromLayers, verifyProofSha256 } from './utils/merkle.js'
import { bufToHex, hexToBuf } from './utils/bytes.js'
import { uploadChunk, uploadManifest } from './utils/api.js'

const CHUNK_SIZE = 4 * 1024 * 1024 // 4MB

const short = (s, n = 10) => (s?.length > 2*n ? `${s.slice(0,n)}…${s.slice(-n)}` : s)
const ts = () => new Date().toLocaleTimeString()

export default function App() {
  const [file, setFile] = useState(null)
  const [aes, setAes] = useState(null)
  const [layers, setLayers] = useState(null)
  const [rootHex, setRootHex] = useState('')
  const [manifest, setManifest] = useState(null)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState(0)
  const [logs, setLogs] = useState([])
  const [lastChallenge, setLastChallenge] = useState(null)

  const addLog = (text, level = '') =>
    setLogs(prev => [...prev, { time: ts(), text, level }])

  const onPick = (e) => setFile(e.target.files[0] || null)

  async function encryptAndUpload() {
    if (!file) return
    setBusy(true); setLogs([]); setProgress(0)
    addLog(`Selected file: ${file.name} (${file.size} bytes)`, 'acc')

    const { key, rawHex } = await genAESKey()
    setAes({ key, rawHex })
    addLog(`Generated AES-256-GCM key`, 'ok')

    const input = new Uint8Array(await file.arrayBuffer())
    const leaves = []; const chunkCIDs = []; const ivs = []

    let idx = 0
    for (let off=0; off<input.length; off+=CHUNK_SIZE, idx++) {
      const chunk = input.slice(off, Math.min(input.length, off+CHUNK_SIZE))
      addLog(`Chunk ${idx}: ${chunk.length} bytes`)
      const { iv, ciphertext } = await aesGcmEncrypt(key, chunk)
      const leaf = await sha256(ciphertext.buffer)
      leaves.push(leaf); ivs.push(bufToHex(iv.buffer))
      addLog(`  iv: ${bufToHex(iv.buffer)}`)
      addLog(`  leaf: ${bufToHex(leaf.buffer)}`)

      const { cid } = await uploadChunk(`chunk-${idx}.bin`, ciphertext, idx)
      chunkCIDs.push(cid)
      addLog(`  uploaded → CID: ${cid}`, 'ok')
      setProgress(Math.round(((idx+1) / Math.ceil(input.length / CHUNK_SIZE)) * 100))
    }

    const tree = await buildSha256Tree(leaves)
    setLayers(tree.layers)
    const rootHex = bufToHex(tree.root.buffer)
    setRootHex(rootHex)
    addLog(`Merkle root (SHA-256): ${rootHex}`, 'acc')

    const man = {
      version: 3,
      fileName: file.name,
      totalSize: file.size,
      chunkSize: CHUNK_SIZE,
      leaves: leaves.map(u8 => bufToHex(u8.buffer)),
      merkleRootSHA256: rootHex,
      chunkCIDs,
      ivs,
      algo: { hash: 'sha256', enc: 'aes-256-gcm' }
    }

    const { cid: manifestCid } = await uploadManifest(man)
    setManifest({ ...man, manifestCid })
    addLog(`Manifest uploaded → CID: ${manifestCid}`, 'ok')

    setBusy(false)
  }

  async function runChallenge() {
    if (!layers || !manifest) return
    setBusy(true)
    const idx = Math.floor(Math.random() * manifest.leaves.length)
    addLog(`Challenge start → index ${idx}`, 'warn')

    const cid = manifest.chunkCIDs[idx]
    const url = `https://w3s.link/ipfs/${cid}`
    addLog(`  fetch ${short(url, 30)}`)

    const r = await fetch(url)
    if (!r.ok) { addLog(`  fetch failed HTTP ${r.status}`, 'err'); setBusy(false); return }
    const enc = new Uint8Array(await r.arrayBuffer())
    addLog(`  received ${enc.length} bytes`)

    const leafHash = await sha256(enc.buffer)
    addLog(`  computed leaf: ${bufToHex(leafHash.buffer)}`)

    const proof = merkleProofFromLayers(layers, idx)
    addLog(`  merkle siblings: ${proof.length}`)

    const rootBuf = new Uint8Array(hexToBuf(manifest.merkleRootSHA256))
    const ok = await verifyProofSha256(leafHash, new Uint8Array(rootBuf), proof)

    if (ok) {
      addLog(`Challenge OK for index ${idx}`, 'ok')
      setLastChallenge({ idx, cid, ok: true })
    } else {
      addLog(`Challenge FAILED for index ${idx}`, 'err')
      setLastChallenge({ idx, cid, ok: false })
    }
    setBusy(false)
  }

  async function decryptAll() {
    if (!manifest || !aes) return
    setBusy(true); setProgress(0); addLog(`Decrypt start…`, 'warn')

    const out = new Uint8Array(manifest.totalSize)
    let off = 0
    for (let i=0; i<manifest.chunkCIDs.length; i++) {
      const url = `https://w3s.link/ipfs/${manifest.chunkCIDs[i]}`
      addLog(`  fetch chunk[${i}] ${short(url, 30)}`)

      const r = await fetch(url)
      if (!r.ok) { addLog(`  fetch failed HTTP ${r.status}`, 'err'); setBusy(false); return }
      const enc = new Uint8Array(await r.arrayBuffer())
      addLog(`  received ${enc.length} bytes`)

      try {
        const iv = new Uint8Array(hexToBuf(manifest.ivs[i]))
        const pt = await aesGcmDecrypt(aes.key, iv, enc)
        out.set(pt, off); off += pt.length
        addLog(`  decrypted chunk[${i}] (${pt.length} bytes)`, 'ok')
      } catch (e) {
        addLog(`  decrypt error: ${e?.message || e}`, 'err')
        setBusy(false); return
      }
      setProgress(Math.round(((i+1) / manifest.chunkCIDs.length) * 100))
    }

    const blob = new Blob([out], { type:'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `DECRYPTED-${manifest.fileName}`; a.click()
    URL.revokeObjectURL(url)
    addLog(`Decrypt done → downloaded DECRYPTED-${manifest.fileName}`, 'ok')
    setBusy(false)
  }

  return (
    <div className="app">
      <div style={{ display:'flex', alignItems:'baseline', gap:12 }}>
        <div className="h1">Storacha VES — MCP</div>
        <span className="pill">AES-256-GCM</span>
        <span className="pill">SHA-256 Merkle</span>
        {busy ? <span className="pill warn">Working…</span> : <span className="pill ok">Idle</span>}
      </div>
      <div className="subtle" style={{ marginTop: 4 }}>
        Encrypt → Chunk → Upload (MCP) → Manifest → Challenge → Decrypt
      </div>

      <div className="row" style={{ marginTop: 16 }}>
        <div className="card">
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <input type="file" onChange={onPick} />
            <button className="btn" onClick={encryptAndUpload} disabled={!file || busy}>Encrypt & Upload</button>
            <button className="btn" onClick={runChallenge} disabled={!layers || busy}>Challenge</button>
            <button className="btn" onClick={decryptAll} disabled={!manifest || !aes || busy}>Decrypt</button>
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="progress"><div style={{ width: `${progress}%` }} /></div>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap: 12, marginTop: 16 }}>
            <div className="kv">
              <div className="k">File</div><div className="v">{manifest?.fileName || file?.name || '-'}</div>
              <div className="k">Size</div><div className="v">{manifest?.totalSize ?? file?.size ?? '-'}</div>
              <div className="k">Chunks</div><div className="v">{manifest?.chunkCIDs?.length ?? '-'}</div>
              <div className="k">Merkle Root</div><div className="v">{short(rootHex, 16) || '-'}</div>
              <div className="k">Manifest CID</div><div className="v">{manifest?.manifestCid ? short(manifest.manifestCid, 16) : '-'}</div>
              <div className="k">AES Key</div><div className="v">{aes?.rawHex ? short(aes.rawHex, 16) : '-'}</div>
            </div>

            <div className="kv">
              <div className="k">Last Challenge</div>
              <div className="v">
                {lastChallenge
                  ? <>
                      index <b>{lastChallenge.idx}</b> — {short(lastChallenge.cid, 12)} — {lastChallenge.ok
                        ? <span className="pill ok">OK</span>
                        : <span className="pill err">FAILED</span>}
                    </>
                  : '—'}
              </div>

              <div className="k">First Chunk CID</div>
              <div className="v">{manifest?.chunkCIDs?.[0] ? short(manifest.chunkCIDs[0], 16) : '-'}</div>
              <div className="k">First IV</div>
              <div className="v">{manifest?.ivs?.[0] ? manifest.ivs[0] : '-'}</div>
              <div className="k">Hash[0] (expected)</div>
              <div className="v">{manifest?.leaves?.[0] ? short(manifest.leaves[0], 16) : '-'}</div>
            </div>
          </div>
        </div>

        <div className="card">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'baseline' }}>
            <div style={{ fontWeight: 700 }}>Live Logs</div>
            <button className="btn" onClick={() => setLogs([])} disabled={busy}>Clear</button>
          </div>
          <div style={{ marginTop: 10 }}>
            <LogPanel lines={logs} />
          </div>
        </div>
      </div>
    </div>
  )
}