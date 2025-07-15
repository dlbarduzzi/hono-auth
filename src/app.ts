import { routes } from "@/core/routes"
import { bootstrap, newApp } from "@/core/app"

const app = newApp()
bootstrap(app)

app.route("/", routes)

export { app }
