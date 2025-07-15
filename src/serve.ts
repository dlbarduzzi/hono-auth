import { serve } from "@hono/node-server"

import { env } from "@/core/env"
import { logger } from "@/core/logger"

import { app } from "./app"

serve({
  port: env.APP_PORT,
  fetch: app.fetch,
}, info => {
  logger.info("app running", { port: info.port })
})
