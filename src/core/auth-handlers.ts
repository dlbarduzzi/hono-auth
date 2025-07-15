import type { AppHandler } from "./types"

export const login: AppHandler = async ctx => {
  return ctx.json(
    {
      ok: true,
      status: "Ok",
      message: "User logged in successfully.",
    },
    200,
  )
}
