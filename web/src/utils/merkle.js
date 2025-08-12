import { sha256 } from './crypto.js'
import { bufToHex } from './bytes.js' 
const concat = (a,b) => { const out = new Uint8Array(a.length+b.length); out.set(a); out.set(b,a.length); return out }

export async function buildSha256Tree(leaves) {
  const layers = [leaves]
  let cur = leaves
  while (cur.length > 1) {
    const next = []
    for (let i=0;i<cur.length;i+=2) {
      const L = cur[i], R = (i+1<cur.length)? cur[i+1]:cur[i]
      next.push(await sha256(concat(L,R)))
    }
    layers.push(next); cur = next
  }
  return { root: cur[0], layers }
}

export function merkleProofFromLayers(layers, leafIndex) {
  const proof = []; let idx = leafIndex
  for (let level=0; level<layers.length-1; level++) {
    const layer = layers[level]
    const right = idx % 2 === 1
    const pair = right ? idx-1 : idx+1
    const sibling = layer[pair] || layer[idx]
    proof.push({ sibling, isRightSibling: !right })
    idx = Math.floor(idx/2)
  }
  return proof
}

export async function verifyProofSha256(leafHash, root, proof) {
    let acc = leafHash
    for (const { sibling, isRightSibling } of proof) {
      const combined = isRightSibling
        ? new Uint8Array([...acc, ...sibling])
        : new Uint8Array([...sibling, ...acc])
      acc = await sha256(combined)
    }
    // Compare hex strings instead of Buffer
    return bufToHex(acc.buffer) === bufToHex(root.buffer)
  }