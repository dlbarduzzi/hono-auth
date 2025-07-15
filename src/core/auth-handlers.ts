import type { AppHandler } from "./types"

import { setSessionCookie } from "./cookie"

export const login: AppHandler = async ctx => {
  await setSessionCookie(
    ctx,
    { id: "user-1", email: "test@email.com" },
    { id: "session-1", token: "abcd-1234-efgh-5678" },
    true,
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
