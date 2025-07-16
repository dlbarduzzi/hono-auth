import type { AppHandler } from "./types"

import z from "zod"

import { lowercase } from "./strings"
import { setSessionCookie } from "./cookie"

import { loginSchema } from "./auth-schemas"
import { generateId } from "./security"

export const login: AppHandler = async ctx => {
  const input = await ctx.req.json()
  const parsed = loginSchema.safeParse(input)

  if (!parsed.success) {
    return ctx.json(
      {
        ok: false,
        status: "Bad Request",
        message: "Invalid JSON payload.",
        error: z.treeifyError(parsed.error).properties,
      },
      400,
    )
  }

  let { email, rememberMe } = parsed.data
  email = lowercase(email)

  const user = { id: "user-1", email }
  const session = { id: "session-1", token: generateId(32) }

  await setSessionCookie(
    ctx,
    user,
    session,
    rememberMe,
  )
  return ctx.json(
    {
      ok: true,
      status: "Ok",
      message: "User logged in successfully.",
    },
    200,
  )
}
