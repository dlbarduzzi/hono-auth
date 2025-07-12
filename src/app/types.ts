import type { Logger } from "winston"

export type AppEnv = {
  Variables: {
    logger: Logger
  }
}
