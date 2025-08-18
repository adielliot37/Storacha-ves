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

export async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
  
  const raw = await crypto.subtle.exportKey('raw', key)
  return { key, rawHex: bufToHex(raw) }
}

export async function exportEncryptedKey(aesKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const { key: derivedKey } = await deriveKeyFromPassword(password, salt)
  
  const keyData = await crypto.subtle.exportKey('raw', aesKey)
  const { iv, ciphertext } = await aesGcmEncrypt(derivedKey, new Uint8Array(keyData))
  
  const exportData = {
    version: 1,
    salt: bufToHex(salt.buffer),
    iv: bufToHex(iv.buffer),
    encryptedKey: bufToHex(ciphertext.buffer),
    timestamp: Date.now()
  }
  
  return JSON.stringify(exportData, null, 2)
}

export async function importEncryptedKey(exportedData, password) {
  const data = JSON.parse(exportedData)
  if (data.version !== 1) throw new Error('Unsupported key file version')
  
  const salt = new Uint8Array(bufFromHex(data.salt))
  const iv = new Uint8Array(bufFromHex(data.iv))
  const encryptedKey = new Uint8Array(bufFromHex(data.encryptedKey))
  
  const { key: derivedKey } = await deriveKeyFromPassword(password, salt)
  const keyData = await aesGcmDecrypt(derivedKey, iv, encryptedKey)
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
  
  return { key, rawHex: bufToHex(keyData.buffer) }
}

function bufFromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  }
  return bytes.buffer
}