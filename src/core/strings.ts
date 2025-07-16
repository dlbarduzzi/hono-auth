export function lowercase(str: string) {
  return str.toLowerCase()
}

export function uppercase(str: string) {
  return str.toUpperCase()
}

export function capitalize(str: string) {
  return str.charAt(0).toUpperCase() + str.slice(1)
}

export function strings(str: string) {
  return {
    hasNumber: () => {
      return /[0-9]/.test(str)
    },
    hasSpecialChar: () => {
      return /[!?@#$&^*_\-=+]/.test(str)
    },
    hasLowercaseChar: () => {
      return /[a-z]/.test(str)
    },
    hasUppercaseChar: () => {
      return /[A-Z]/.test(str)
    },
  }
}
