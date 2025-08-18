import express from 'express'
import multer from 'multer'
import cors from 'cors'
import dotenv from 'dotenv'
dotenv.config()

const app = express()
const upload = multer({ storage: multer.memoryStorage() })
const PORT = process.env.PORT || 8787
const MCP_URL = process.env.MCP_REST_URL
const DELEGATION = process.env.DELEGATION
const ORIGIN = process.env.CLIENT_ORIGIN

if (!MCP_URL || !DELEGATION) {
  console.error('Missing MCP_REST_URL or DELEGATION in .env')
  process.exit(1)
}

app.use(cors({ origin: ORIGIN }))
app.get('/health', (_req, res) => res.json({ ok: true }))

async function mcpUploadBase64({ base64, name }) {
    const rpcBody = {
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: { name: 'upload', arguments: { file: base64, name, delegation: DELEGATION } }
    };
  
    const r = await fetch(MCP_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rpcBody) });
    if (!r.ok) throw new Error(`MCP upload HTTP ${r.status}`);
    const j = await r.json();
  
  
    console.log('🛰 MCP full response:', JSON.stringify(j, null, 2));
  
    const text = j?.result?.content?.[0]?.text;
    if (!text) throw new Error('MCP upload: missing result.content[0].text');
    
    let payload;
    try {
      payload = JSON.parse(text);
    } catch (parseError) {
      // If parsing fails, check if it's an error response
      if (text.includes('error') || text.includes('Error')) {
        throw new Error(`MCP upload error: ${text}`);
      }
      throw new Error(`MCP upload: invalid JSON response: ${text}`);
    }

    // Check for error in payload
    if (payload.error) {
      throw new Error(`MCP upload error: ${payload.error}`);
    }
  
    // Try to find the file CID with multiple fallback strategies
    let fileCid = payload?.files?.[name]?.['/'];
    
    // If not found with exact name, try other strategies
    if (!fileCid && payload?.files) {
      const keys = Object.keys(payload.files);
      
      // Strategy 1: Try the first available file
      if (keys.length > 0) {
        fileCid = payload.files[keys[0]]?.['/'];
        console.log(`Using first available file: ${keys[0]} -> ${fileCid}`);
      }
      
      // Strategy 2: Try without extension if original had one
      if (!fileCid && name.includes('.')) {
        const nameWithoutExt = name.split('.')[0];
        for (const key of keys) {
          if (key.startsWith(nameWithoutExt)) {
            fileCid = payload.files[key]?.['/'];
            console.log(`Matched by prefix: ${key} -> ${fileCid}`);
            break;
          }
        }
      }
    }
    
    if (!fileCid) {
      const keys = payload?.files ? Object.keys(payload.files) : [];
      throw new Error(`MCP upload: file CID not found for "${name}". Available keys: ${keys.join(', ')}. Payload: ${JSON.stringify(payload, null, 2)}`);
    }
  
   
    const rootCid = payload?.root?.['/'];
  
    return { fileCid, rootCid, payload };
  }
  
  app.post('/upload-chunk', upload.single('chunk'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'no chunk' });
      const index = Number(req.body.index ?? 0);
      const name  = req.body.name || `chunk-${index}.bin`;
  
      const base64 = Buffer.from(req.file.buffer).toString('base64');
      const { fileCid } = await mcpUploadBase64({ base64, name });
  
      
      res.json({ cid: fileCid });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  });
  
  app.post('/upload-manifest', upload.single('manifest'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'no manifest' });
      const base64 = Buffer.from(req.file.buffer).toString('base64');
  
      // important: name must match the key MCP returns in payload.files
      const { fileCid } = await mcpUploadBase64({ base64, name: 'manifest.json' });
  
      // ✅ return manifest **file** CID
      res.json({ cid: fileCid });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  });

app.listen(PORT, () => console.log(`VES server (MCP REST) on :${PORT}`))