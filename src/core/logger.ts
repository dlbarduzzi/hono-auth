import { env } from "./env"
import { createLogger, format, transports } from "winston"

export const logger = createLogger({
  level: env.LOG_LEVEL,
  format: format.combine(format.timestamp(), format.json()),
  silent: env.NODE_ENV === "test" || env.LOG_LEVEL === "silent",
  transports: [new transports.Console()],
})
