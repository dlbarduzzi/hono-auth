import type { AppEnv } from "./types"

import { Hono } from "hono"

export function newApp() {
  return new Hono<AppEnv>({ strict: false })
}
