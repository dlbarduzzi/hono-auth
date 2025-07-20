import { capitalize } from "@/tools/strings/strings"

export const HOST_COOKIE_PREFIX = "__Host-"
export const SECURE_COOKIE_PREFIX = "__Secure-"

type Cookie = Map<string, string>

export type CookieOptions = {
  domain?: string
  expires?: Date
  httpOnly?: boolean
  maxAge?: number
  partitioned?: boolean
  path?: string
  secure?: boolean
  sameSite?: "Strict" | "Lax" | "None"
  priority?: "Low" | "Medium" | "High"
}

export function parseCookie(name: string, cookie: string): Cookie {
  const parsedCookie: Cookie = new Map()

  if (!cookie.includes(name)) {
    return parsedCookie
  }

  const pairs = cookie.trim().split(";")

  for (let pair of pairs) {
    pair = pair.trim()

    const index = pair.indexOf("=")
    if (index < 0) {
      continue
    }

    const cookieName = pair.substring(0, index).trim()
    const cookieValue = decodeURIComponent(pair.substring(index + 1).trim())

    if (name !== cookieName) {
      continue
    }

    parsedCookie.set(cookieName, cookieValue)
  }

  return parsedCookie
}

export function serializeCookie(name: string, value: string, options: CookieOptions) {
  let cookie = `${name}=${encodeURIComponent(value)}`

  if (name.startsWith(SECURE_COOKIE_PREFIX) && !options.secure) {
    throw new Error(`${SECURE_COOKIE_PREFIX} cookie must have Secure attribute`)
  }

  if (name.startsWith(HOST_COOKIE_PREFIX)) {
    if (!options.secure) {
      throw new Error(`${HOST_COOKIE_PREFIX} cookie must have Secure attribute`)
    }

    if (options.path !== "/") {
      // eslint-disable-next-line style/max-len
      throw new Error(`${HOST_COOKIE_PREFIX} cookie must have Path attribute set to "/"`)
    }

    if (options.domain) {
      throw new Error(`${HOST_COOKIE_PREFIX} cookie must not have Domain attribute`)
    }
  }

  if (options && typeof options.maxAge === "number" && options.maxAge >= 0) {
    if (options.maxAge > 34560000) {
      throw new Error("Cookie Max-Age attribute must not be greater than 400 days")
    }
    cookie += `; Max-Age=${options.maxAge | 0}`
  }

  if (options.domain && !name.startsWith(HOST_COOKIE_PREFIX)) {
    cookie += `; Domain=${options.domain}`
  }

  if (options.path) {
    cookie += `; Path=${options.path}`
  }

  if (options.expires) {
    if (options.expires.getTime() - Date.now() > 34560000_000) {
      throw new Error("Cookie Expires attribute must not be greater than 400 days")
    }
    cookie += `; Expires=${options.expires.toUTCString()}`
  }

  if (options.httpOnly) {
    cookie += `; HttpOnly`
  }

  if (options.secure) {
    cookie += `; Secure`
  }

  if (options.sameSite) {
    cookie += `; SameSite=${capitalize(options.sameSite)}`
  }

  if (options.priority) {
    cookie += `; Priority=${options.priority}`
  }

  if (options.partitioned) {
    if (!options.secure) {
      throw new Error("Cookie Partitioned must have Secure attribute")
    }
    cookie += "; Partitioned"
  }

  return cookie
}
