import { z } from "zod"
import { config } from "dotenv"
import { expand } from "dotenv-expand"

expand(config({ quiet: true }))

const schema = z.object({
  NODE_ENV: z.enum(["test", "development", "production"]),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error", "silent"]),
  APP_URL: z.url(),
  APP_PORT: z.coerce.number().int().positive(),
})

// eslint-disable-next-line node/no-process-env
const parsed = schema.safeParse(process.env)

if (!parsed.success) {
  console.error(
    "❌ Invalid environment variables ❌",
    JSON.stringify(parsed.error.issues, null, 2),
  )
  // eslint-disable-next-line node/no-process-exit
  process.exit(1)
}

export const env = parsed.data
