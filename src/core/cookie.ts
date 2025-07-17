import type { AppContext } from "./types"

import { env } from "./env"
import { hmac } from "./hmac"
import { capitalize } from "./strings"

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

type ParsedCookie = { [key: string]: string }
type SignedCookie = { [key: string]: string }

function parseCookie(name: string, cookie: string) {
  const cookieObject: ParsedCookie = {}

  if (!cookie.includes(name)) {
    return cookieObject
  }

  const pairs = cookie.trim().split(";")

  for (const pair of pairs) {
    const valueStartIndex = pair.indexOf("=")
    if (valueStartIndex < 0) {
      continue
    }

    const cookieName = pair.substring(0, valueStartIndex).trim()
    if (name !== cookieName) {
      continue
    }

    const cookieValue = pair.substring(valueStartIndex + 1).trim()
    cookieObject[cookieName] = cookieValue
  }

  return cookieObject
}

async function parseSignedCookie(name: string, secret: string, cookie: string) {
  const signedCookie: SignedCookie = {}
  const parsedCookie = parseCookie(name, cookie)

  for (const [key, value] of Object.entries(parsedCookie)) {
    const signatureStartIndex = value.lastIndexOf(".")
    if (signatureStartIndex < 0) {
      continue
    }

    const cookieValue = value.substring(0, signatureStartIndex)
    const cookieSignature = value.substring(signatureStartIndex + 1)

    const isVerified = cookieSignature === secret
    signedCookie[key] = isVerified ? cookieValue : ""
  }

  return signedCookie
}

async function getSignedCookie(name: string, secret: string, headers: Headers) {
  const cookie = headers.get("Cookie")
  return await parseSignedCookie(name, secret, cookie ?? "")
}

function _serialize(name: string, value: string, options: CookieOptions) {
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
  const signature = await hmac.sign(value, secret)
  value = `${value}.${signature}`
  value = encodeURIComponent(value)
  return _serialize(name, value, options)
}

async function setSignedCookie(
  ctx: AppContext,
  name: string,
  value: string,
  secret: string,
  options: CookieOptions,
) {
  const cookie = await serializeSignedCookie(
    name,
    value,
    secret,
    options,
  )
  ctx.header("Set-Cookie", cookie, { append: true })
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

export async function setSessionCookie(
  ctx: AppContext,
  _: UserSchema,
  session: SessionSchema,
  rememberMe?: boolean,
) {
  const testCookie = await getSignedCookie(
    "hono-auth.remember_me",
    env.COOKIE_SECRET,
    ctx.req.raw.headers,
  )
  console.warn({ testCookie })

  const rememberMeCookie = await getSignedCookie(
    "rememberMe",
    env.COOKIE_SECRET,
    ctx.req.raw.headers,
  )
  rememberMe = rememberMe !== undefined ? rememberMe : !!rememberMeCookie

  const cookie = createCookie("session_token", {
    expires: rememberMe
      ? new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) // 7 days
      : new Date(Date.now() + 1000 * 60 * 60 * 24 * 1), // 1 day
  })

  await setSignedCookie(
    ctx,
    cookie.name,
    session.token,
    env.COOKIE_SECRET,
    cookie.options,
  )

  if (!rememberMe) {
    const cookie = createCookie("remember_me", {
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 days
    })

    await setSignedCookie(
      ctx,
      cookie.name,
      "false",
      env.COOKIE_SECRET,
      cookie.options,
    )
  }
}
