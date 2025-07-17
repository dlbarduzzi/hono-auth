import { subtle } from "uncrypto"

import { hex } from "./hex"

const algorithm = { name: "HMAC", hash: { name: "SHA-256" } }

export const hmac = {
  key: async (secret: string) => {
    return await subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      algorithm,
      false,
      ["sign", "verify"],
    )
  },
  sign: async (value: string, secret: string) => {
    const cryptoKey = await hmac.key(secret)
    const signature = await subtle.sign(
      algorithm.name,
      cryptoKey,
      new TextEncoder().encode(value),
    )
    return hex.encode(signature)
  },
  verify: async (value: string, secret: string, hexSignature: string) => {
    const buffer = new Uint8Array(hexSignature.length / 2)
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = Number.parseInt(hexSignature.slice(i * 2, i * 2 + 2), 16)
    }
    const cryptoKey = await hmac.key(secret)
    const signature = new Uint8Array(buffer)
    return await subtle.verify(
      algorithm.name,
      cryptoKey,
      signature,
      new TextEncoder().encode(value),
    )
  },
}
