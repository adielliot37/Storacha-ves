import React, { useState, useEffect } from 'react'
import LogPanel from './components/LogPanel.jsx'
import { genAESKey, aesGcmEncrypt, aesGcmDecrypt, sha256, exportEncryptedKey, importEncryptedKey, deriveKeyFromPassword } from './utils/crypto.js'
import { buildSha256Tree, merkleProofFromLayers, verifyProofSha256 } from './utils/merkle.js'
import { bufToHex, hexToBuf } from './utils/bytes.js'
import { uploadChunk, uploadManifest } from './utils/api.js'
import { generateSemanticEmbedding, encryptSemanticData, advancedSearch, configureOpenAI, isSemanticSearchAvailable, getSearchSuggestions } from './utils/semantic.js'

const CHUNK_SIZE = 4 * 1024 * 1024 // 4MB
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB

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
  const [keySource, setKeySource] = useState('') // 'generated', 'imported', 'derived'
  const [showKeyManager, setShowKeyManager] = useState(false)
  const [showWarning, setShowWarning] = useState(true)
  const [isDragging, setIsDragging] = useState(false)
  const [fileError, setFileError] = useState('')
  const [uploadStartTime, setUploadStartTime] = useState(null)
  const [manifestHistory, setManifestHistory] = useState([])
  const [showHistory, setShowHistory] = useState(false)
  
  // Semantic search state
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [isSearching, setIsSearching] = useState(false)
  const [searchSuggestions, setSearchSuggestions] = useState([])
  const [semanticSearchEnabled, setSemanticSearchEnabled] = useState(false)

  const addLog = (text, level = '') =>
    setLogs(prev => [...prev, { time: ts(), text, level }])

  useEffect(() => {
    const saved = localStorage.getItem('ves-manifest-history')
    if (saved) {
      try {
        setManifestHistory(JSON.parse(saved))
      } catch (e) {
        console.warn('Failed to load manifest history:', e)
      }
    }
    
    // Check if semantic search is available on server
    isSemanticSearchAvailable().then(available => {
      if (available) {
        setSemanticSearchEnabled(true)
        addLog('AI semantic search enabled', 'ok')
      }
    }).catch(error => {
      console.warn('Failed to check semantic search availability:', error)
    })
  }, [])

  const saveManifestToHistory = (manifest) => {
    const historyEntry = {
      ...manifest,
      timestamp: Date.now(),
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    }
    
    const newHistory = [historyEntry, ...manifestHistory].slice(0, 10) // Keep last 10
    setManifestHistory(newHistory)
    localStorage.setItem('ves-manifest-history', JSON.stringify(newHistory))
  }

  const loadManifestFromHistory = (historyEntry) => {
    setManifest(historyEntry)
    setRootHex(historyEntry.merkleRootSHA256)
    setFile(null) // Clear current file selection
    
    // Rebuild layers from manifest for challenge functionality
    if (historyEntry.leaves) {
      const leaves = historyEntry.leaves.map(hex => new Uint8Array(hexToBuf(hex)))
      buildSha256Tree(leaves).then(tree => {
        setLayers(tree.layers)
      })
    }
    
    addLog(`Loaded manifest: ${historyEntry.fileName} (${(historyEntry.totalSize / 1024 / 1024).toFixed(2)} MB)`, 'ok')
    addLog(`Manifest CID: ${historyEntry.manifestCid}`, 'acc')
  }

  const clearManifestHistory = () => {
    if (confirm('Clear all manifest history? This cannot be undone.')) {
      setManifestHistory([])
      localStorage.removeItem('ves-manifest-history')
      addLog('Manifest history cleared', 'warn')
    }
  }

  const exportManifestHistory = () => {
    if (manifestHistory.length === 0) {
      addLog('No manifest history to export', 'warn')
      return
    }

    try {
      const exportData = {
        version: '1.0',
        exportDate: new Date().toISOString(),
        deviceInfo: `${navigator.userAgent.split(' ')[0]} on ${navigator.platform}`,
        totalFiles: manifestHistory.length,
        manifests: manifestHistory
      }

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ves-manifest-backup-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)

      addLog(`Exported ${manifestHistory.length} file manifests to backup file`, 'ok')
      addLog('Keep this file safe to restore your file list on any device', 'acc')
    } catch (e) {
      addLog(`Export failed: ${e.message}`, 'err')
    }
  }

  const importManifestHistory = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = async (e) => {
      const file = e.target.files[0]
      if (!file) return

      try {
        const text = await file.text()
        const importData = JSON.parse(text)

        // Validate the backup file format
        if (!importData.version || !importData.manifests || !Array.isArray(importData.manifests)) {
          throw new Error('Invalid backup file format')
        }

        const action = confirm(
          `Import ${importData.totalFiles || importData.manifests.length} files from backup?\n\n` +
          `Backup created: ${new Date(importData.exportDate).toLocaleString()}\n` +
          `Device: ${importData.deviceInfo || 'Unknown'}\n\n` +
          `This will ${manifestHistory.length > 0 ? 'merge with' : 'replace'} your current history.`
        )

        if (!action) return

        // Merge with existing history, avoiding duplicates
        const existingIds = new Set(manifestHistory.map(m => m.id))
        const newManifests = importData.manifests.filter(m => !existingIds.has(m.id))
        const mergedHistory = [...manifestHistory, ...newManifests].slice(0, 50) // Increase limit for imports
        
        setManifestHistory(mergedHistory)
        localStorage.setItem('ves-manifest-history', JSON.stringify(mergedHistory))

        const importedCount = newManifests.length
        const skippedCount = importData.manifests.length - importedCount

        addLog(`Imported ${importedCount} new file manifests`, 'ok')
        if (skippedCount > 0) {
          addLog(`Skipped ${skippedCount} duplicate files`, 'warn')
        }
        addLog(`Total files in history: ${mergedHistory.length}`, 'acc')

      } catch (e) {
        addLog(`Import failed: ${e.message}`, 'err')
        if (e.message.includes('JSON')) {
          addLog('Invalid backup file - must be a VES manifest backup JSON file', 'err')
        }
      }
    }
    input.click()
  }

  const validateFile = (file) => {
    setFileError('')
    if (!file) return false
    
    if (file.size > MAX_FILE_SIZE) {
      setFileError(`File size (${(file.size / 1024 / 1024).toFixed(1)}MB) exceeds the 10MB limit. Please choose a smaller file.`)
      return false
    }
    
    return true
  }

  const onPick = (e) => {
    const selectedFile = e.target.files[0] || null
    if (selectedFile && validateFile(selectedFile)) {
      setFile(selectedFile)
    } else if (selectedFile) {
      setFile(null)
    }
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile && validateFile(droppedFile)) {
      setFile(droppedFile)
    }
  }

  async function ensureEncryptionKey() {
    // If we already have a key, use it
    if (aes && aes.key) {
      addLog(`Using existing ${keySource} key`, 'ok')
      return aes
    }

    // No key available - prompt user for action
    const action = prompt(
      'No encryption key found. Choose an option:\n' +
      '1. Generate new key (will auto-download encrypted backup)\n' +
      '2. Import existing key file\n' +
      '3. Derive from password\n\n' +
      'Enter 1, 2, or 3:'
    )

    if (!action) {
      throw new Error('Key setup cancelled by user')
    }

    switch (action.trim()) {
      case '1':
        // Generate new key and auto-download
        const { key: newKey, rawHex: newRawHex } = await genAESKey()
        const newAes = { key: newKey, rawHex: newRawHex }
        setAes(newAes)
        setKeySource('generated')
        addLog('Generated new AES-256-GCM key', 'ok')
        
        // Auto-download encrypted key backup
        await autoDownloadKeyBackup(newKey)
        return newAes

      case '2':
        // Import key
        const importedKey = await importKey()
        if (!importedKey) throw new Error('Key import was cancelled or failed')
        return importedKey

      case '3':
        // Derive from password  
        const derivedKey = await deriveKey()
        if (!derivedKey) throw new Error('Key derivation was cancelled or failed')
        return derivedKey

      default:
        throw new Error('Invalid option selected')
    }
  }

  async function autoDownloadKeyBackup(key) {
    try {
      const password = prompt('Create a password to encrypt your key backup file:')
      if (!password) {
        addLog('Key backup skipped - no password provided', 'warn')
        return
      }

      addLog('Creating automatic key backup...', 'warn')
      const exportedData = await exportEncryptedKey(key, password)
      
      const blob = new Blob([exportedData], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ves-key-backup-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
      
      addLog('Key backup automatically downloaded!', 'ok')
    } catch (e) {
      addLog(`Auto-backup failed: ${e.message}`, 'err')
      addLog('You can manually export your key later', 'warn')
    }
  }

  async function encryptAndUpload() {
    if (!file) return
    setBusy(true); setLogs([]); setProgress(0); setFileError('')
    setUploadStartTime(Date.now())
    addLog(`Selected file: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`, 'acc')

    let encryptionKey
    try {
      // Ensure we have an encryption key (existing or new)
      encryptionKey = await ensureEncryptionKey()
      if (!encryptionKey) {
        setBusy(false)
        return
      }
    } catch (e) {
      addLog(e.message, 'err')
      setBusy(false)
      return
    }

    const input = new Uint8Array(await file.arrayBuffer())
    const leaves = []; const chunkCIDs = []; const ivs = []

    let idx = 0
    for (let off=0; off<input.length; off+=CHUNK_SIZE, idx++) {
      const chunk = input.slice(off, Math.min(input.length, off+CHUNK_SIZE))
      addLog(`Chunk ${idx}: ${chunk.length} bytes`)
      const { iv, ciphertext } = await aesGcmEncrypt(encryptionKey.key, chunk)
      const leaf = await sha256(ciphertext.buffer)
      leaves.push(leaf); ivs.push(bufToHex(iv.buffer))
      addLog(`  iv: ${bufToHex(iv.buffer)}`)
      addLog(`  leaf: ${bufToHex(leaf.buffer)}`)

      const { cid } = await uploadChunk(`chunk-${idx}.bin`, ciphertext, idx)
      chunkCIDs.push(cid)
      addLog(`  uploaded → CID: ${cid}`, 'ok')
      
      const progressPercent = Math.round(((idx+1) / Math.ceil(input.length / CHUNK_SIZE)) * 100)
      setProgress(progressPercent)
      
      if (uploadStartTime) {
        const elapsedTime = Date.now() - uploadStartTime
        const estimatedTotal = elapsedTime / (progressPercent / 100)
        const remainingTime = estimatedTotal - elapsedTime
        addLog(`  Progress: ${progressPercent}% | ETA: ${Math.round(remainingTime / 1000)}s`)
      }
    }

    const tree = await buildSha256Tree(leaves)
    setLayers(tree.layers)
    const rootHex = bufToHex(tree.root.buffer)
    setRootHex(rootHex)
    addLog(`Merkle root (SHA-256): ${rootHex}`, 'acc')

    // Generate semantic embeddings if OpenAI is configured
    let semanticData = null
    if (semanticSearchEnabled) {
      try {
        addLog('Generating semantic embeddings...', 'warn')
        const embedding = await generateSemanticEmbedding(file)
        semanticData = await encryptSemanticData(embedding, encryptionKey.key)
        addLog('Semantic data encrypted and ready', 'ok')
      } catch (error) {
        addLog(`Semantic embedding failed: ${error.message}`, 'warn')
        addLog('File will be uploaded without semantic search capability', 'warn')
      }
    }

    const man = {
      version: 3,
      fileName: file.name,
      totalSize: file.size,
      chunkSize: CHUNK_SIZE,
      leaves: leaves.map(u8 => bufToHex(u8.buffer)),
      merkleRootSHA256: rootHex,
      chunkCIDs,
      ivs,
      algo: { hash: 'sha256', enc: 'aes-256-gcm' },
      ...(semanticData && { semanticData })
    }

    const { cid: manifestCid } = await uploadManifest(man)
    const finalManifest = { ...man, manifestCid }
    setManifest(finalManifest)
    saveManifestToHistory(finalManifest)
    addLog(`Manifest uploaded → CID: ${manifestCid}`, 'ok')
    
    // Update search suggestions after successful upload
    if (semanticSearchEnabled && aes) {
      setTimeout(loadSearchSuggestions, 1000)
    }

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
    if (!r.ok) { 
      addLog(`  fetch failed: HTTP ${r.status} - ${r.statusText}`, 'err')
      addLog(`  Check network connection and try again`, 'err')
      setBusy(false); return 
    }
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
    if (!manifest || !aes) {
      addLog('Missing manifest or decryption key', 'err')
      return
    }
    
    setBusy(true); setProgress(0); 
    addLog(`Starting decryption of ${manifest.fileName} (${(manifest.totalSize / 1024 / 1024).toFixed(2)} MB)`, 'warn')
    addLog(`Key source: ${keySource} | Chunks: ${manifest.chunkCIDs.length}`, 'acc')

    const startTime = Date.now()
    const out = new Uint8Array(manifest.totalSize)
    let off = 0
    let retryCount = 0
    const maxRetries = 3
    
    for (let i=0; i<manifest.chunkCIDs.length; i++) {
      const url = `https://w3s.link/ipfs/${manifest.chunkCIDs[i]}`
      let success = false
      
      // Retry logic for network issues
      for (let attempt = 1; attempt <= maxRetries && !success; attempt++) {
        try {
          addLog(`  fetching chunk[${i}/${manifest.chunkCIDs.length}]${attempt > 1 ? ` (attempt ${attempt})` : ''}`)

          const r = await fetch(url)
          if (!r.ok) { 
            throw new Error(`HTTP ${r.status} - ${r.statusText}`)
          }
          
          const enc = new Uint8Array(await r.arrayBuffer())
          addLog(`  received ${enc.length} bytes`)

          const iv = new Uint8Array(hexToBuf(manifest.ivs[i]))
          const pt = await aesGcmDecrypt(aes.key, iv, enc)
          out.set(pt, off); off += pt.length
          addLog(`  decrypted chunk[${i}] (${pt.length} bytes)`, 'ok')
          
          success = true
          
        } catch (e) {
          retryCount++
          if (attempt === maxRetries) {
            addLog(`  chunk ${i} failed after ${maxRetries} attempts: ${e?.message || e}`, 'err')
            if (e.message && e.message.includes('decrypt')) {
              addLog(`  Decryption failed - wrong key or corrupted data`, 'err')
            } else {
              addLog(`  Network or IPFS error - file may no longer be available`, 'err')
            }
            setBusy(false); 
            return
          } else {
            addLog(`  attempt ${attempt} failed: ${e?.message || e}, retrying...`, 'warn')
            await new Promise(resolve => setTimeout(resolve, 1000 * attempt)) // exponential backoff
          }
        }
      }
      
      const progressPercent = Math.round(((i+1) / manifest.chunkCIDs.length) * 100)
      setProgress(progressPercent)
      
      // ETA calculation
      const elapsed = Date.now() - startTime
      const eta = elapsed / (i+1) * (manifest.chunkCIDs.length - i - 1)
      if (eta > 1000) {
        addLog(`  progress: ${progressPercent}% | ETA: ${Math.round(eta / 1000)}s`)
      }
    }

    try {
      const blob = new Blob([out], { type:'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `DECRYPTED-${manifest.fileName}`; a.click()
      URL.revokeObjectURL(url)
      
      const totalTime = Math.round((Date.now() - startTime) / 1000)
      addLog(`Decryption completed in ${totalTime}s → downloaded DECRYPTED-${manifest.fileName}`, 'ok')
      if (retryCount > 0) {
        addLog(`Note: ${retryCount} retries were needed due to network issues`, 'warn')
      }
    } catch (e) {
      addLog(`Download failed: ${e.message}`, 'err')
    }
    
    setBusy(false)
  }

  async function exportKey() {
    if (!aes) return
    const password = prompt('Enter password to encrypt the key file:')
    if (!password) return
    
    try {
      setBusy(true)
      addLog('Exporting encrypted key...', 'warn')
      const exportedData = await exportEncryptedKey(aes.key, password)
      
      const blob = new Blob([exportedData], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ves-key-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
      
      addLog('Key exported successfully', 'ok')
    } catch (e) {
      addLog(`Export failed: ${e.message}`, 'err')
      addLog(`Try again with a different password or check browser permissions`, 'err')
    }
    setBusy(false)
  }

  async function importKey() {
    return new Promise((resolve) => {
      const input = document.createElement('input')
      input.type = 'file'
      input.accept = '.json'
      input.onchange = async (e) => {
        const file = e.target.files[0]
        if (!file) {
          resolve()
          return
        }
        
        const password = prompt('Enter password to decrypt the key file:')
        if (!password) {
          resolve()
          return
        }
        
        try {
          addLog('Importing encrypted key...', 'warn')
          const text = await file.text()
          const { key, rawHex } = await importEncryptedKey(text, password)
          
          setAes({ key, rawHex })
          setKeySource('imported')
          addLog('Key imported successfully', 'ok')
          resolve({ key, rawHex })
        } catch (e) {
          addLog(`Import failed: ${e.message}`, 'err')
          if (e.message.includes('decrypt')) {
            addLog(`Wrong password or corrupted key file`, 'err')
          } else {
            addLog(`Invalid key file format or browser issue`, 'err')
          }
          resolve()
        }
      }
      input.click()
    })
  }

  const checkPasswordStrength = (password) => {
    let strength = 0
    let feedback = []
    
    if (password.length >= 8) strength += 1
    else feedback.push('At least 8 characters')
    
    if (/[A-Z]/.test(password)) strength += 1
    else feedback.push('One uppercase letter')
    
    if (/[a-z]/.test(password)) strength += 1
    else feedback.push('One lowercase letter')
    
    if (/[0-9]/.test(password)) strength += 1
    else feedback.push('One number')
    
    if (/[^A-Za-z0-9]/.test(password)) strength += 1
    else feedback.push('One special character')
    
    const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong']
    return {
      score: strength,
      level: levels[strength],
      feedback,
      color: ['#f87171', '#fb923c', '#fbbf24', '#a3e635', '#22c55e'][strength]
    }
  }

  async function deriveKey() {
    let password = ''
    let isValidPassword = false
    
    while (!isValidPassword) {
      password = prompt('Enter password to derive encryption key (min 8 chars with mixed case, numbers, and symbols):')
      if (!password) return null
      
      const strength = checkPasswordStrength(password)
      if (strength.score >= 3) {
        isValidPassword = true
      } else {
        const missing = strength.feedback.join(', ')
        const retry = confirm(`Password strength: ${strength.level}\nMissing: ${missing}\n\nUse this password anyway? (Not recommended)`)
        if (retry) isValidPassword = true
      }
    }
    
    try {
      addLog('Deriving key from password...', 'warn')
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const { key, rawHex } = await deriveKeyFromPassword(password, salt)
      
      setAes({ key, rawHex })
      setKeySource('derived')
      addLog('Key derived from password', 'ok')
      return { key, rawHex }
    } catch (e) {
      addLog(`Key derivation failed: ${e.message}`, 'err')
      return null
    }
  }

  function clearKey() {
    if (!confirm('Are you sure you want to clear the current key? This cannot be undone.')) return
    setAes(null)
    setKeySource('')
    addLog('Key cleared', 'warn')
  }


  // Load search suggestions
  const loadSearchSuggestions = async () => {
    if (!aes || !semanticSearchEnabled) return
    
    try {
      const suggestions = await getSearchSuggestions(manifestHistory, aes.key)
      setSearchSuggestions(suggestions)
    } catch (error) {
      console.warn('Failed to load search suggestions:', error)
    }
  }

  // Perform semantic search
  const performSearch = async () => {
    if (!searchQuery.trim() || !aes || !semanticSearchEnabled) return
    
    setIsSearching(true)
    setSearchResults([])
    
    try {
      addLog(`Searching for: "${searchQuery}"`, 'warn')
      const results = await advancedSearch(searchQuery.trim(), manifestHistory, aes.key, {
        maxResults: 10,
        semanticThreshold: 0.25  // Lower threshold for better matches
      })
      
      setSearchResults(results)
      addLog(`Found ${results.length} matching files`, results.length > 0 ? 'ok' : 'warn')
      
      if (results.length === 0) {
        addLog('Try different keywords or upload more files with semantic data', 'acc')
      }
    } catch (error) {
      addLog(`Search failed: ${error.message}`, 'err')
      if (error.message.includes('API key')) {
        addLog('Check your OpenAI API key configuration', 'err')
      }
    }
    
    setIsSearching(false)
  }


  return (
    <div className="app">
      <div style={{ 
        display:'flex', 
        alignItems:'center', 
        justifyContent:'space-between',
        marginBottom: 8,
        flexWrap: 'wrap',
        gap: 12
      }}>
        <div>
          <div className="h1" style={{ marginBottom: 4 }}>Storacha VES</div>
          <div className="subtle" style={{ fontSize: '14px' }}>
            Verifiable Encrypted Storage with Merkle Challenge Protocol
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="pill">AES-256-GCM</span>
          <span className="pill">SHA-256 Merkle</span>
          {busy ? <span className="pill warn">Working…</span> : <span className="pill ok">Ready</span>}
        </div>
      </div>

      {showWarning && (
        <div style={{ 
          marginTop: 12, 
          padding: 12, 
          backgroundColor: '#2a1f0a', 
          border: '1px solid #fbbf24', 
          borderRadius: 4,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          color: '#fbbf24'
        }}>
          <div>
            <strong>⚠️ Key Management Notice:</strong>
            <br />
            • Generated keys auto-download encrypted backup files
            <br />
            • Keys are <strong>lost on page refresh</strong> - keep your backup files safe
            <br />
            • Import previous keys or derive from password to decrypt files
            <br />
            • Use the same key to encrypt multiple files efficiently
          </div>
          <button 
            onClick={() => setShowWarning(false)}
            style={{ 
              background: 'none', 
              border: 'none', 
              fontSize: '18px', 
              cursor: 'pointer',
              padding: '0 4px',
              color: '#fbbf24'
            }}
          >
            ×
          </button>
        </div>
      )}

      {manifestHistory.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div className="card" style={{ backgroundColor: '#1a2a1a', border: '1px solid #36d399' }}>
            <div style={{ marginBottom: 16 }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', fontWeight: 600, color: '#36d399' }}>📁 Previously Uploaded Files</h3>
              <div style={{ fontSize: '14px', color: 'var(--muted)', marginBottom: 12 }}>
                You have {manifestHistory.length} file{manifestHistory.length === 1 ? '' : 's'} available for decryption. Load any file to challenge or download it.
              </div>
              <div style={{ maxHeight: 150, overflowY: 'auto', display: 'grid', gap: 8 }}>
                {manifestHistory.slice(0, 3).map((entry) => (
                  <div key={entry.id} style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    padding: '8px 12px',
                    backgroundColor: 'var(--panel)',
                    borderRadius: '6px',
                    border: manifest?.id === entry.id ? '1px solid var(--accent)' : '1px solid var(--border)'
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: '13px', color: manifest?.id === entry.id ? 'var(--accent)' : 'inherit' }}>
                        {entry.fileName}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                        {(entry.totalSize / 1024 / 1024).toFixed(1)} MB • {new Date(entry.timestamp).toLocaleDateString()}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button 
                        className="btn" 
                        onClick={() => loadManifestFromHistory(entry)}
                        disabled={manifest?.id === entry.id}
                        style={{ fontSize: '11px', padding: '4px 8px' }}
                      >
                        {manifest?.id === entry.id ? 'Active' : 'Load'}
                      </button>
                      {manifest?.id === entry.id && (
                        aes ? (
                          <button 
                            className="btn"
                            onClick={decryptAll}
                            disabled={busy}
                            style={{ fontSize: '11px', padding: '4px 8px', backgroundColor: 'var(--ok)' }}
                          >
                            Download
                          </button>
                        ) : (
                          <div style={{ fontSize: '10px', color: 'var(--err)', textAlign: 'center' }}>
                            Need key to decrypt
                          </div>
                        )
                      )}
                    </div>
                  </div>
                ))}
                {manifestHistory.length > 3 && (
                  <button 
                    className="btn" 
                    onClick={() => setShowHistory(true)}
                    style={{ fontSize: '12px', padding: '6px', textAlign: 'center' }}
                  >
                    View all {manifestHistory.length} files...
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Semantic Search Interface */}
      {semanticSearchEnabled && (
        <div style={{ marginTop: 16 }}>
          <div className="card" style={{ backgroundColor: '#1a2a2a', border: '1px solid #36d399' }}>
            <div style={{ marginBottom: 16 }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', fontWeight: 600, color: '#36d399', display: 'flex', alignItems: 'center', gap: 8 }}>
                AI Semantic Search
                <span className="pill ok" style={{ fontSize: '11px' }}>Enabled</span>
              </h3>
              
              <div style={{ fontSize: '14px', color: 'var(--muted)', marginBottom: 12 }}>
                Search your encrypted files by meaning, not just keywords. All processing happens client-side with your encrypted data.
              </div>

              <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performSearch()}
                  placeholder="Search your files... (e.g., 'contract with red logo', 'python code', 'last week documents')"
                  style={{
                    flex: 1,
                    minWidth: '250px',
                    padding: '8px 12px',
                    backgroundColor: 'var(--panel)',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    color: 'inherit',
                    fontSize: '14px'
                  }}
                  disabled={!aes || isSearching}
                />
                <button 
                  className="btn" 
                  onClick={performSearch}
                  disabled={!searchQuery.trim() || !aes || isSearching}
                  style={{ backgroundColor: 'var(--accent)', minWidth: '100px' }}
                >
                  {isSearching ? 'Searching...' : 'Search'}
                </button>
              </div>

              {/* Search Suggestions */}
              {searchSuggestions.length > 0 && !searchQuery && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: 6 }}>Quick suggestions:</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {searchSuggestions.map((suggestion, idx) => (
                      <button
                        key={idx}
                        className="btn"
                        onClick={() => setSearchQuery(suggestion.text)}
                        style={{ 
                          fontSize: '11px', 
                          padding: '4px 8px',
                          backgroundColor: 'var(--panel)',
                          border: '1px solid var(--border)'
                        }}
                      >
                        {suggestion.icon} {suggestion.text}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Search Results */}
              {searchResults.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: 8, color: 'var(--accent)' }}>
                    Found {searchResults.length} matching files:
                  </div>
                  <div style={{ maxHeight: '200px', overflowY: 'auto', display: 'grid', gap: 6 }}>
                    {searchResults.map((result, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '8px 12px',
                          backgroundColor: 'var(--panel)',
                          borderRadius: '6px',
                          border: '1px solid var(--border)',
                          cursor: 'pointer'
                        }}
                        onClick={() => loadManifestFromHistory(result.manifest)}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 600, fontSize: '13px' }}>
                              {result.manifest.fileName}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                              {(result.manifest.totalSize / 1024).toFixed(1)}KB • 
                              Relevance: {(result.totalScore * 100).toFixed(0)}% • 
                              {result.matchTypes?.map(m => m.type).join(', ')}
                            </div>
                            {result.textPreview && (
                              <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 2, fontStyle: 'italic' }}>
                                "{result.textPreview.substring(0, 80)}..."
                              </div>
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: 4 }}>
                            <span className={`pill ${result.relevanceLevel === 'high' ? 'ok' : result.relevanceLevel === 'medium' ? 'warn' : ''}`} 
                                  style={{ fontSize: '10px' }}>
                              {result.relevanceLevel}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {searchQuery && searchResults.length === 0 && !isSearching && (
                <div style={{ textAlign: 'center', color: 'var(--muted)', fontSize: '14px', padding: '12px' }}>
                  No matching files found. Try different keywords or upload more files.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="row" style={{ marginTop: 16 }}>
        <div className="card">
          <div style={{ marginBottom: 20 }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', fontWeight: 600 }}>File Operations</h3>
            <div style={{ display:'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, gridColumn: 'span 2' }}>
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  style={{
                    border: isDragging ? '2px dashed var(--accent)' : '2px dashed var(--border)',
                    borderRadius: '12px',
                    padding: '20px',
                    textAlign: 'center',
                    backgroundColor: isDragging ? 'rgba(124, 157, 255, 0.1)' : 'var(--panel)',
                    transition: 'all 0.3s ease',
                    cursor: 'pointer',
                    position: 'relative'
                  }}
                >
                  <input 
                    type="file" 
                    onChange={onPick}
                    style={{ 
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      height: '100%',
                      opacity: 0,
                      cursor: 'pointer'
                    }}
                  />
                  <div style={{ pointerEvents: 'none' }}>
                    {file ? (
                      <div>
                        <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: 4 }}>
                          {file.name}
                        </div>
                        <div style={{ fontSize: '14px', color: 'var(--muted)' }}>
                          {(file.size / 1024 / 1024).toFixed(2)} MB
                        </div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontSize: '16px', marginBottom: 4 }}>
                          {isDragging ? 'Drop file here' : 'Drag & drop or click to select'}
                        </div>
                        <div style={{ fontSize: '14px', color: 'var(--muted)' }}>
                          Maximum file size: 10 MB
                        </div>
                      </div>
                    )}
                  </div>
                </div>
                
                {fileError && (
                  <div style={{ 
                    padding: '8px 12px', 
                    backgroundColor: '#2a1f1f', 
                    border: '1px solid var(--err)',
                    borderRadius: '6px',
                    color: 'var(--err)',
                    fontSize: '13px'
                  }}>
                    {fileError}
                  </div>
                )}
              </div>
              <button className="btn" onClick={encryptAndUpload} disabled={!file || busy}>
                Encrypt & Upload
              </button>
              <button className="btn" onClick={runChallenge} disabled={!layers || busy}>
                Challenge
              </button>
              <button className="btn" onClick={decryptAll} disabled={!manifest || !aes || busy}>
                Decrypt & Download
              </button>
            </div>
          </div>
          
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', fontWeight: 600 }}>Key Management</h3>
            <div style={{ display:'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10 }}>
              <button className="btn key-btn import" onClick={importKey} disabled={busy || aes}>
                Import Key
              </button>
              <button className="btn key-btn derive" onClick={deriveKey} disabled={busy || aes}>
                Derive Key  
              </button>
              <button className="btn key-btn export" onClick={exportKey} disabled={!aes || busy}>
                Export Key
              </button>
              <button className="btn key-btn clear" onClick={clearKey} disabled={!aes || busy}>
                Clear Key
              </button>
              <button className="btn" onClick={() => setShowHistory(!showHistory)} disabled={busy}>
                {showHistory ? 'Hide History' : `Show History (${manifestHistory.length})`}
              </button>
            </div>
            
            <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', fontWeight: 600, color: 'var(--accent)' }}>🔄 File List Backup</h4>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="btn" onClick={importManifestHistory} disabled={busy} style={{ fontSize: '12px', padding: '6px 12px' }}>
                  📁 Import File List
                </button>
                <button className="btn" onClick={exportManifestHistory} disabled={busy || manifestHistory.length === 0} style={{ fontSize: '12px', padding: '6px 12px' }}>
                  💾 Export File List
                </button>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--muted)', marginTop: 6 }}>
                Backup your file list to access from any device. Works with same encryption key.
              </div>
            </div>
            
            {showHistory && (
              <div style={{ marginTop: 16, padding: 12, backgroundColor: 'var(--panel)', borderRadius: 8, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>Manifest History ({manifestHistory.length})</h4>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn" onClick={importManifestHistory} disabled={busy} style={{ fontSize: '11px', padding: '3px 6px', backgroundColor: 'var(--accent)' }}>
                      📁 Import Backup
                    </button>
                    {manifestHistory.length > 0 && (
                      <>
                        <button className="btn" onClick={exportManifestHistory} disabled={busy} style={{ fontSize: '11px', padding: '3px 6px', backgroundColor: 'var(--ok)' }}>
                          💾 Export Backup
                        </button>
                        <button className="btn" onClick={clearManifestHistory} style={{ fontSize: '11px', padding: '3px 6px' }}>
                          🗑️ Clear All
                        </button>
                      </>
                    )}
                  </div>
                </div>
                
                {manifestHistory.length === 0 ? (
                  <div style={{ textAlign: 'center', color: 'var(--muted)', fontSize: '14px', padding: 16 }}>
                    No previous uploads found. Encrypt some files to see them here for future access.
                  </div>
                ) : (
                  <div style={{ maxHeight: 250, overflowY: 'auto' }}>
                    {manifestHistory.map((entry, idx) => (
                      <div key={entry.id} style={{ 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        padding: '12px 0',
                        borderBottom: idx < manifestHistory.length - 1 ? '1px solid var(--border)' : 'none',
                        backgroundColor: manifest?.id === entry.id ? 'rgba(124, 157, 255, 0.1)' : 'transparent',
                        borderRadius: manifest?.id === entry.id ? '4px' : '0',
                        paddingLeft: manifest?.id === entry.id ? '8px' : '0',
                        paddingRight: manifest?.id === entry.id ? '8px' : '0'
                      }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ 
                            fontWeight: 600, 
                            fontSize: '13px', 
                            color: manifest?.id === entry.id ? 'var(--accent)' : 'inherit',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6
                          }}>
                            {manifest?.id === entry.id && <span style={{ fontSize: '10px' }}>●</span>}
                            {entry.fileName}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--muted)', marginTop: 2 }}>
                            {new Date(entry.timestamp).toLocaleString()} • {(entry.totalSize / 1024 / 1024).toFixed(2)} MB • {entry.chunkCIDs?.length || 0} chunks
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 2 }}>
                            CID: {short(entry.manifestCid, 12)}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexDirection: 'column' }}>
                          <button 
                            className="btn" 
                            onClick={() => loadManifestFromHistory(entry)}
                            disabled={manifest?.id === entry.id}
                            style={{ fontSize: '11px', padding: '3px 6px', minWidth: '50px' }}
                          >
                            {manifest?.id === entry.id ? 'Active' : 'Load'}
                          </button>
                          {manifest?.id === entry.id && (
                            aes ? (
                              <button 
                                className="btn"
                                onClick={decryptAll}
                                disabled={busy}
                                style={{ fontSize: '10px', padding: '2px 4px', backgroundColor: 'var(--ok)' }}
                              >
                                Download
                              </button>
                            ) : (
                              <div style={{ fontSize: '9px', color: 'var(--err)', textAlign: 'center', padding: '2px' }}>
                                Need key
                              </div>
                            )
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          
          {aes && (
            <div style={{ 
              marginTop: 16,
              padding: 12, 
              backgroundColor: keySource === 'generated' ? '#2a1f0a' : '#1a2a1a', 
              borderRadius: 8, 
              fontSize: '13px',
              color: keySource === 'generated' ? '#fbbf24' : '#36d399',
              border: `1px solid ${keySource === 'generated' ? '#fbbf24' : '#36d399'}`,
              display: 'flex',
              alignItems: 'center',
              gap: 8
            }}>
              <span style={{ fontSize: '16px' }}>
                {keySource === 'generated' ? '⚠️' : ''}
              </span>
              <div>
                <strong>Key Status:</strong> {keySource === 'generated' ? 'Generated (will be lost on refresh)' : 
                                              keySource === 'imported' ? 'Imported from file' : 
                                              keySource === 'derived' ? 'Derived from password' : 'Unknown'}
                {keySource === 'generated' && (
                  <div style={{ marginTop: 4, fontWeight: 600 }}>
                    Export your key immediately to save it!
                  </div>
                )}
              </div>
            </div>
          )}

          <div style={{ marginTop: 16 }}>
            <div className="progress"><div style={{ width: `${progress}%` }} /></div>
          </div>

          <div style={{ marginTop: 20 }}>
            <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', fontWeight: 600 }}>File Information</h3>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap: 20 }} className="responsive-grid">
              
              <div>
                <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, color: 'var(--accent)' }}>File Details</h4>
                <div className="data-grid">
                  <div className="label">File</div>
                  <div className="value">{manifest?.fileName || file?.name || '—'}</div>
                  
                  <div className="label">Size</div>
                  <div className="value">{manifest?.totalSize ?? file?.size ?? '—'}</div>
                  
                  <div className="label">Chunks</div>
                  <div className="value">{manifest?.chunkCIDs?.length ?? '—'}</div>
                  
                  <div className="label">Merkle Root</div>
                  <div className="value">{short(rootHex, 16) || '—'}</div>
                  
                  <div className="label">Manifest CID</div>
                  <div className="value" style={{ cursor: manifest?.manifestCid ? 'pointer' : 'default' }} 
                       onClick={manifest?.manifestCid ? () => {
                         navigator.clipboard.writeText(manifest.manifestCid)
                         addLog('Manifest CID copied to clipboard', 'ok')
                       } : undefined}
                       title={manifest?.manifestCid ? 'Click to copy full CID' : ''}>
                    {manifest?.manifestCid ? short(manifest.manifestCid, 16) : '—'}
                  </div>
                </div>
              </div>

              <div>
                <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, color: 'var(--accent)' }}>Security & Status</h4>
                <div className="data-grid">
                  <div className="label">AES Key</div>
                  <div className="value">{aes?.rawHex ? short(aes.rawHex, 16) : '—'}</div>
                  
                  <div className="label">Key Source</div>
                  <div className="value">{keySource || '—'}</div>
                  
                  <div className="label">First Chunk CID</div>
                  <div className="value">{manifest?.chunkCIDs?.[0] ? short(manifest.chunkCIDs[0], 16) : '—'}</div>
                  
                  <div className="label">First IV</div>
                  <div className="value">{manifest?.ivs?.[0] || '—'}</div>
                  
                  <div className="label">Hash[0]</div>
                  <div className="value">{manifest?.leaves?.[0] ? short(manifest.leaves[0], 16) : '—'}</div>
                </div>
                
                {lastChallenge && (
                  <div style={{ marginTop: 16, padding: 10, backgroundColor: 'var(--panel)', borderRadius: 6, border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: 6, color: 'var(--accent)' }}>Last Challenge</div>
                    <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
                      Index <strong>{lastChallenge.idx}</strong> • {short(lastChallenge.cid, 12)}
                      <span style={{ marginLeft: 8 }}>
                        {lastChallenge.ok
                          ? <span className="pill ok">PASSED</span>
                          : <span className="pill err">FAILED</span>}
                      </span>
                    </div>
                  </div>
                )}
              </div>
              
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