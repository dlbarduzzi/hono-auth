import { Hono } from "hono"
import { serve } from "@hono/node-server"

import { logger } from "@/core/logger"

const app = new Hono()

app.get("/", (c) => {
  return c.text("Hello Hono!")
})

serve({
  fetch: app.fetch,
  port: 3000,
}, (info) => {
  logger.info("app running", { port: info.port })
})
