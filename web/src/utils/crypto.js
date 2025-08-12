import { bufToHex } from './bytes.js'

export async function sha256(buf) {
  const h = await crypto.subtle.digest('SHA-256', buf)
  return new Uint8Array(h)
}
export async function genAESKey() {
  const key = await crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt'])
  const raw = await crypto.subtle.exportKey('raw', key)
  return { key, rawHex: bufToHex(raw) }
}
export function randIV() { return crypto.getRandomValues(new Uint8Array(12)) }
export async function aesGcmEncrypt(aesKey, bytes) {
  const iv = randIV()
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, bytes)
  return { iv, ciphertext: new Uint8Array(ct) }
}
export async function aesGcmDecrypt(aesKey, iv, ciphertext) {
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ciphertext)
  return new Uint8Array(pt)
}