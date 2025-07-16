export const hex = {
  encode: (data: ArrayBuffer) => {
    if (data.byteLength === 0) {
      return ""
    }
    const buffer = new Uint8Array(data)
    const result = Array.from(buffer)
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("")
    return result
  },
}
