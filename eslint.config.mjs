import antfu from "@antfu/eslint-config"

export default antfu({
  type: "app",
  formatters: true,
  typescript: true,
  stylistic: {
    semi: false,
    quotes: "double",
    indent: 2,
  },
  ignores: ["node_modules/**", "src/db/migrations/**"],
}, {
  rules: {
    "antfu/if-newline": "off",
    "no-empty": "error",
    "no-empty-function": "error",
    "node/no-process-env": "error",
    "node/no-process-exit": "error",
    "node/prefer-global/process": "off",
    "prefer-const": "error",
    "perfectionist/sort-imports": "off",
    "perfectionist/sort-named-imports": "off",
    "regexp/prefer-d": "off",
    "regexp/no-useless-escape": "off",
    "regexp/no-unused-capturing-group": "off",
    "regexp/strict": "off",
    "style/arrow-parens": "off",
    "style/jsx-curly-newline": "off",
    "style/max-len": ["error", { code: 88 }],
    "style/multiline-ternary": "off",
    "style/operator-linebreak": "off",
    "style/quotes": "error",
    "ts/no-unused-vars": ["error", {
      args: "all",
      argsIgnorePattern: "^_$",
      varsIgnorePattern: "^_$",
    }],
    "ts/no-explicit-any": "error",
    "ts/no-unused-expressions": "off",
    "ts/consistent-type-definitions": "off",
    "unicorn/filename-case": ["error", {
      case: "kebabCase",
      ignore: ["README.md", "LICENSE"],
    }],
  },
})
