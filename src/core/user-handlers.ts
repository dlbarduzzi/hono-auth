import type { AppHandler } from "./types"

import { env } from "./env"
import { cookies, getCacheCookie, getSignedCookie } from "./cookie"

export const getSession: AppHandler = async ctx => {
  const sessionTokenCookie = cookies.sessionToken(false)

  const tokenCookie = await getSignedCookie(
    sessionTokenCookie.name,
    env.COOKIE_SECRET,
    ctx.req.raw.headers,
  )

  const cookieValue = tokenCookie[sessionTokenCookie.name]

  if (!cookieValue) {
    return ctx.json(
      {
        ok: true,
        session: null,
      },
      200,
    )
  }

  const dataCookie = await getCacheCookie(ctx.req.raw.headers)

  return ctx.json(
    {
      ok: true,
      session: dataCookie,
    },
    200,
  )
}
