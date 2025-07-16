import postgres from "postgres"

import { env } from "@/core/env"
import { drizzle } from "drizzle-orm/postgres-js"

import {
  users,
  userRelations,
  sessions,
  sessionRelations,
  passwords,
} from "./schemas"

const schema = {
  users,
  userRelations,
  sessions,
  sessionRelations,
  passwords,
}

const client = postgres(env.DATABASE_URL)
const connect = drizzle({ client, schema })

export const db = connect
export type DB = typeof db
