import { bootstrap, newApp } from "@/core/app"

const app = newApp()
bootstrap(app)

app.get("/", ctx => {
  return ctx.text("Hello!")
})

export { app }
