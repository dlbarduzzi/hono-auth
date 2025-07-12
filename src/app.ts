import { newApp } from "@/app/main"

const app = newApp()

app.get("/", (c) => {
  return c.text("Welcome, Hono!")
})

export { app }
