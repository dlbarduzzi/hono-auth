import type { DB } from "@/db/connect"
import type { Logger } from "winston"
import type { Context, Handler, Hono } from "hono"

export type AppEnv = {
  Variables: {
    db: DB
    logger: Logger
  }
}

export type App = Hono<AppEnv>
export type AppContext = Context<AppEnv>
export type AppHandler = Handler<AppEnv>
