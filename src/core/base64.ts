function getAlphabet(urlSafe: boolean): string {
  return urlSafe
    ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
}

function encodeBase64(data: Uint8Array, padding: boolean, alphabet: string) {
  let shift = 0
  let buffer = 0
  let result = ""

  for (const byte of data) {
    shift += 8
    buffer = (buffer << 8) | byte
    while (shift >= 6) {
      shift -= 6
      result += alphabet[(buffer >> shift) & 0x3F]
    }
  }

  if (shift > 0) {
    result += alphabet[(buffer << (6 - shift)) & 0x3F]
  }

  if (padding) {
    const padCount = (4 - (result.length % 4)) % 4
    result += "=".repeat(padCount)
  }

  return result
}

function decodeBase64(data: string, alphabet: string) {
  const decodeMap = new Map<string, number>()
  for (let i = 0; i < alphabet.length; i++) {
    decodeMap.set(alphabet[i]!, i)
  }

  const result: number[] = []

  let buffer = 0
  let bitsCollected = 0

  for (const char of data) {
    if (char === "=") {
      break
    }

    const value = decodeMap.get(char)
    if (value === undefined) {
      throw new Error(`Invalid base64 character: ${char}`)
    }

    buffer = (buffer << 6) | value
    bitsCollected += 6

    if (bitsCollected >= 8) {
      bitsCollected -= 8
      result.push((buffer >> bitsCollected) & 0xFF)
    }
  }

  return Uint8Array.from(result)
}

export const base64 = {
  encode(data: string | ArrayBuffer, padding: boolean, urlSafe: boolean) {
    const buffer = typeof data === "string"
      ? new TextEncoder().encode(data)
      : new Uint8Array(data)
    const alphabet = getAlphabet(urlSafe)
    return encodeBase64(buffer, padding, alphabet)
  },
  decode(data: string) {
    const urlSafe = data.includes("-") || data.includes("_")
    const alphabet = getAlphabet(urlSafe)
    return decodeBase64(data, alphabet)
  },
}
