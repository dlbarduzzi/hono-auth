import { newApp } from "./app"

import { login } from "./auth-handlers"

const app = newApp()

app.post("/api/v1/auth/login", login)

export const routes = app
