import { Hono } from "hono"
import { serve } from "@hono/node-server"

const app = new Hono()

app.get("/", (c) => {
  return c.text("Hello Hono!")
})

serve({
  port: 3000,
  fetch: app.fetch,
}, (info) => {
  // eslint-disable-next-line no-console
  console.log(`Server is running on http://localhost:${info.port}`)
})
