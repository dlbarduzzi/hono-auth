import { newApp } from "./app"

import { login } from "./auth-handlers"
import { getSession } from "./user-handlers"

const app = newApp()

app.post("/api/v1/auth/login", login)
app.get("/api/v1/user/get-session", getSession)

export const routes = app
