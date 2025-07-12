import type { Hono } from "hono"
import type { Logger } from "winston"

export type AppEnv = {
  Variables: {
    logger: Logger
  }
}

export type App = Hono<AppEnv>
