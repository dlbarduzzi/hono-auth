import { describe, expect, it } from "vitest"
import { parseCookie, serializeCookie } from "./cookie"

describe("parse cookie", () => {
  const cookie = "cookie_one=value-one; cookie_two=value-two"
  it("should parse cookie one", () => {
    const parsedCookie = parseCookie("cookie_one", cookie)
    expect(parsedCookie.get("cookie_one")).toBe("value-one")
  })
  it("should parse cookie two", () => {
    const parsedCookie = parseCookie("cookie_two", cookie)
    expect(parsedCookie.get("cookie_two")).toBe("value-two")
  })
  it("should parse not found cookie", () => {
    const parsedCookie = parseCookie("cookie_three", cookie)
    expect(parsedCookie.get("cookie_three")).toBe(undefined)
  })
  it("should parse invalid cookie", () => {
    const parsedCookie = parseCookie("invalid", "cookie_invalid")
    expect(parsedCookie.size).toBe(0)
  })
})

describe("serialize cookie", () => {
  it("should serialize cookie", () => {
    const cookie = serializeCookie("cookie_one", "value-one", {})
    expect(cookie).toBe("cookie_one=value-one")
  })

  it("should serialize cookie with all secure options", () => {
    const cookie = serializeCookie("__Secure-cookie_one", "value-one", {
      domain: "test.com",
      expires: new Date(Date.UTC(2000, 11, 24, 10, 30, 59, 900)),
      httpOnly: true,
      maxAge: 1000,
      partitioned: true,
      path: "/",
      secure: true,
      sameSite: "Strict",
      priority: "High",
    })
    expect(cookie).toBe(
      // eslint-disable-next-line style/max-len
      "__Secure-cookie_one=value-one; Max-Age=1000; Domain=test.com; Path=/; Expires=Sun, 24 Dec 2000 10:30:59 GMT; HttpOnly; Secure; SameSite=Strict; Priority=High; Partitioned",
    )
  })

  it("should serialize cookie with all host options", () => {
    const cookie = serializeCookie("__Host-cookie_one", "value-one", {
      expires: new Date(Date.UTC(2000, 11, 24, 10, 30, 59, 900)),
      httpOnly: true,
      maxAge: 1000,
      partitioned: true,
      path: "/",
      secure: true,
      sameSite: "Strict",
      priority: "High",
    })
    expect(cookie).toBe(
      // eslint-disable-next-line style/max-len
      "__Host-cookie_one=value-one; Max-Age=1000; Path=/; Expires=Sun, 24 Dec 2000 10:30:59 GMT; HttpOnly; Secure; SameSite=Strict; Priority=High; Partitioned",
    )
  })

  it("should serialize cookie with max-age 0", () => {
    const serialized = serializeCookie("cookie_one", "value-one", { maxAge: 0 })
    expect(serialized).toBe("cookie_one=value-one; Max-Age=0")
  })

  it("should serialize cookie with max-age -1", () => {
    const serialized = serializeCookie("cookie_one", "value-one", { maxAge: -1 })
    expect(serialized).toBe("cookie_one=value-one")
  })

  it("should throw error cookie without secure attribute", () => {
    expect(() => {
      serializeCookie("__Secure-cookie_one", "value-one", {
        secure: false,
      })
    }).toThrowError("__Secure- cookie must have Secure attribute")
    expect(() => {
      serializeCookie("__Host-cookie_one", "value-one", {
        secure: false,
      })
    }).toThrowError("__Host- cookie must have Secure attribute")
  })

  it("should throw error host cookie with invalid domain", () => {
    expect(() => {
      serializeCookie("__Host-cookie_one", "value-one", {
        path: "/api",
        secure: true,
      })
    }).toThrowError(`__Host- cookie must have Path attribute set to "/"`)
    expect(() => {
      serializeCookie("__Host-cookie_one", "value-one", {
        path: "/",
        secure: true,
      })
    }).not.toThrowError()
    expect(() => {
      serializeCookie("__Host-cookie_one", "value-one", {
        domain: "test.com",
        path: "/",
        secure: true,
      })
    }).toThrowError("__Host- cookie must not have Domain attribute")
  })

  it("should throw error cookie with max-age grater than 400 days", () => {
    expect(() => {
      serializeCookie("cookie_one", "value-one", {
        maxAge: 3600 * 24 * 401,
      })
    }).toThrowError("Cookie Max-Age attribute must not be greater than 400 days")
  })

  it("should throw error cookie with expires grater than 400 days", () => {
    expect(() => {
      serializeCookie("cookie_one", "value-one", {
        expires: new Date(new Date().getTime() + 1000 * 60 * 60 * 24 * 402),
      })
    }).toThrowError("Cookie Expires attribute must not be greater than 400 days")
  })

  it("should throw error cookie with invalid partitioned options", () => {
    expect(() => {
      serializeCookie("cookie_one", "value-one", {
        secure: false,
        partitioned: true,
      })
    }).toThrowError("Cookie Partitioned must have Secure attribute")
  })
})
