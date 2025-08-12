const BASE = 'http://localhost:8787'

export async function uploadChunk(name, buf, index) {
  const fd = new FormData()
  fd.append('chunk', new Blob([buf]), name)
  fd.append('name', name)
  fd.append('index', String(index))
  const r = await fetch(`${BASE}/upload-chunk`, { method: 'POST', body: fd })
  if (!r.ok) throw new Error('upload-chunk failed')
  return r.json() // { cid }
}

export async function uploadManifest(manifestObj) {
  const fd = new FormData()
  const bytes = new TextEncoder().encode(JSON.stringify(manifestObj, null, 2))
  fd.append('manifest', new Blob([bytes], { type: 'application/json' }), 'manifest.json')
  const r = await fetch(`${BASE}/upload-manifest`, { method: 'POST', body: fd })
  if (!r.ok) throw new Error('upload-manifest failed')
  return r.json() // { cid }
}