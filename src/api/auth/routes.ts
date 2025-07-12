import { newApp } from "@/app/main"

const app = newApp()

app.post("/login", ctx => {
  return ctx.json({
    ok: true,
    message: "User logged in successfully.",
  }, 200)
})

export const auth = app
