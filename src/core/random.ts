import { getRandomValues } from "uncrypto"

type Alphabet = "a-z" | "A-Z" | "0-9" | "-_"

function getAlphabet(alphabet: Alphabet): string | undefined {
  switch (alphabet) {
    case "a-z":
      return "abcdefghijklmnopqrstuvwxyz"
    case "A-Z":
      return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    case "0-9":
      return "0123456789"
    case "-_":
      return "-_"
    default:
      alphabet satisfies never
  }
}

export function randomStringGenerator<A extends Alphabet>(...givenAlphabet: A[]) {
  const baseCharSet = givenAlphabet.map(getAlphabet).join("")
  const baseCharSetLength = baseCharSet.length

  if (baseCharSetLength === 0) {
    throw new Error("Random string generator must have valid alphabet")
  }

  return <SubA extends Alphabet>(size: number, ...givenAlphabet: SubA[]) => {
    if (size < 1) {
      throw new Error("Random string generator size must be a positive integer")
    }

    let charSet = baseCharSet
    let charSetLength = baseCharSetLength

    if (givenAlphabet.length > 0) {
      charSet = givenAlphabet.map(getAlphabet).join("")
      charSetLength = charSet.length
    }

    const maxValid = Math.floor(256 / charSetLength) * charSetLength

    const buffer = new Uint8Array(size * 2)
    const bufferLength = buffer.length

    let result = ""
    let random: number
    let bufferIndex = bufferLength

    while (result.length < size) {
      if (bufferIndex >= bufferLength) {
        getRandomValues(buffer)
        bufferIndex = 0
      }

      random = buffer[bufferIndex++] ?? 0

      if (random < maxValid) {
        result += charSet[random % charSetLength]
      }
    }

    return result
  }
}
