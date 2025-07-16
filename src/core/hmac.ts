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
}
