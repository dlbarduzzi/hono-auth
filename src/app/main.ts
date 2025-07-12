import type { App, AppEnv } from "./types"

import { Hono } from "hono"
import { requestId } from "hono/request-id"

import { logger } from "@/core/logger"

export function newApp() {
  return new Hono<AppEnv>({ strict: false })
}

export function bootstrap(app: App) {
  app.use("*", requestId())

  app.use("*", async (ctx, next) => {
    ctx.set("logger", logger)
    await next()
  })

  app.use("*", async (ctx, next) => {
    await next()
    logger.info(`${ctx.req.method} ${ctx.req.path} ${ctx.res.status}`)
  })

  app.notFound(ctx => {
    return ctx.text("404 - Not Found", 404)
  })

  app.onError((err, ctx) => {
    console.error(err)
    return ctx.text("500 - Internal Server Error", 500)
  })
}
