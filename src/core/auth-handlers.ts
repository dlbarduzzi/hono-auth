import type { AppHandler } from "./types"
import type { UserSchema, SessionSchema } from "@/db/schemas"

import z from "zod"

import { lowercase } from "./strings"
import { generateId } from "./security"
import { setSessionCookie } from "./cookie"

import { loginSchema } from "./auth-schemas"

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

  const user: UserSchema = {
    id: "user-1",
    email,
    imageUrl: "",
    isEmailVerified: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  }

  const session: SessionSchema = {
    id: "session-1",
    token: generateId(32),
    userId: "",
    ipAddress: "",
    userAgent: "",
    expiresAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  }

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
