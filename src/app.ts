import { auth } from "@/api/auth/routes"
import { bootstrap, newApp } from "@/app/main"

const app = newApp()
bootstrap(app)

app.route("/api/v1/auth", auth)

export { app }
