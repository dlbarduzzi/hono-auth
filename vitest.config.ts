import path, { dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export default defineConfig({
  root: ".",
  test: {
    globals: true,
    coverage: {
      provider: "istanbul",
      reporter: ["text", "html"],
    },
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
    setupFiles: ["vitest.setup.ts"],
  },
})
