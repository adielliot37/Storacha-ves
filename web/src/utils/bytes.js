export const bufToHex = (buf) =>
    Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('')
  export const hexToBuf = (hex) =>
    new Uint8Array(hex.match(/.{1,2}/g).map(h => parseInt(h,16))).buffer