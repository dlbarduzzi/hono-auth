import { randomStringGenerator } from "@/tools/strings/random"

export function generateId(size?: number) {
  return randomStringGenerator("a-z", "A-Z", "0-9")(size || 32)
}
