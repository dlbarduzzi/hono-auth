import type { AppContext } from "./types"

import { env } from "./env"
import { capitalize } from "@/tools/strings"

type UserSchema = {
  id: string
  email: string
}

type SessionSchema = {
  id: string
  token: string
}

type CookieOptions = {
  path?: string
  domain?: string
  maxAge?: number
  secure?: boolean
  expires?: Date
  httpOnly?: boolean
  sameSite?: "Strict" | "Lax" | "None" | "strict" | "lax" | "none"
}

function createCookie(name: string, options?: CookieOptions) {
  const prefix = env.COOKIE_PREFIX
  const cookieName = `${prefix}.${name}`

  const secure = env.APP_URL.startsWith("https://") ?? env.NODE_ENV === "production"
  const secureCookiePrefix = secure ? "__Secure-" : ""

  return {
    name: `${secureCookiePrefix}${cookieName}`,
    options: {
      path: "/",
      secure: !!secureCookiePrefix,
      sameSite: "lax",
      httpOnly: true,
      ...options,
    } as CookieOptions,
  }
}

async function makeSignature(value: string, secret: string) {
  if (1 > 2) {
    console.warn({ value, secret })
  }
  return "make-signature-not-implemented"
}

async function getSignedCookie(name: "other" | "rememberMe") {
  if (name === "rememberMe") {
    return true
  }
  return undefined
}

function _serializeCookie(name: string, value: string, options: CookieOptions) {
  let cookie = `${name}=${value}`

  if (name.startsWith("__Secure-") && !options.secure) {
    throw new Error("__Secure- cookie must have secure option set to true")
  }

  if (name.startsWith("__Host-")) {
    if (!options.secure) {
      throw new Error("__Host- cookie must have secure option set to true")
    }
    if (options.path !== "/") {
      throw new Error("__Host- cookie must have path option set to '/'")
    }
    if (options.domain) {
      throw new Error("__Host- cookie must not have domain option")
    }
  }

  if (options && typeof options.maxAge === "number" && options.maxAge >= 0) {
    if (options.maxAge > 34560000) {
      throw new Error("Cookie max-age must not be greater than 34560000 seconds")
    }
    cookie += `; Max-Age=${options.maxAge | 0}`
  }

  if (options.domain && !name.startsWith("__Host-")) {
    cookie += `; Domain=${options.domain}`
  }

  if (options.path) {
    cookie += `; Path=${options.path}`
  }

  if (options.expires) {
    if (options.expires.getTime() - Date.now() > 34560000_000) {
      throw new Error(
        "Cookie expires must not be greater than 34560000 seconds in the future",
      )
    }
    cookie += `; Expires=${options.expires.toUTCString()}`
  }

  if (options.httpOnly) {
    cookie += "; HttpOnly"
  }

  if (options.secure) {
    cookie += "; Secure"
  }

  if (options.sameSite) {
    cookie += `; SameSite=${capitalize(options.sameSite)}`
  }

  return cookie
}

async function serializeSignedCookie(
  name: string,
  value: string,
  secret: string,
  options: CookieOptions,
) {
  const signature = await makeSignature(value, secret)
  value = `${value}.${signature}`
  value = encodeURIComponent(value)
  return _serializeCookie(name, value, options)
}

async function createSignedCookie(
  name: string,
  value: string,
  secret: string,
  options: CookieOptions,
) {
  const cookie = await serializeSignedCookie(name, value, secret, options)
  return cookie
}

export async function setSessionCookie(
  ctx: AppContext,
  user: UserSchema,
  session: SessionSchema,
  rememberMe?: boolean,
) {
  if (1 > 2) {
    // TODO: Set user in session data.
    console.warn(user)
  }

  const rememberMeCookie = await getSignedCookie("rememberMe")
  rememberMe = rememberMe !== undefined ? rememberMe : !!rememberMeCookie

  const cookie = createCookie("session_token", {
    expires: rememberMe
      ? new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) // 7 days
      : new Date(Date.now() + 1000 * 60 * 60 * 24 * 1), // 1 day
  })

  const signedCookie = await createSignedCookie(
    cookie.name,
    session.token,
    env.COOKIE_SECRET,
    cookie.options,
  )

  ctx.header("Set-Cookie", signedCookie, { append: true })
}
