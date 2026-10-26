import { DatabaseSync, constants as c } from 'node:sqlite'
import { DEFAULT_FUNCTIONS } from './policy.js'
import { PolicyError } from './errors.js'

/**
 * @typedef {{ sql: string, access: Record<string, { read: string[], insert: string[], update: string[], delete: boolean }> }} AuthorizeResult
 */

// Functions SQLite calls on its own when evaluating operators
const OPERATOR_FUNCTIONS = ['like', 'glob', '->', '->>']

/**
 * Second opinion from SQLite itself. Prepares an authorized statement against
 * an empty copy of the schema and lets SQLite's authorizer report every table
 * and column it touches. Anything outside `result.access` fails, which catches
 * cases where the parser and SQLite read the same SQL differently.
 *
 * @param {string} schema CREATE TABLE statements for the real database
 * @param {{ functions?: string[] }} [options]
 */
function createVerifier (schema, options = {}) {
  const db = new DatabaseSync(':memory:')
  db.exec(schema)
  // Foreign key checks show up as reads of the parent table. They are
  // SQLite's own integrity checks, not client access, so leave them out
  db.exec('PRAGMA foreign_keys = OFF')
  const functions = new Set([...(options.functions ?? DEFAULT_FUNCTIONS), ...OPERATOR_FUNCTIONS].map(f => f.toLowerCase()))

  /** @param {AuthorizeResult} result */
  return function verify (result) {
    const access = new Map(Object.entries(result.access).map(([name, a]) => [name.toLowerCase(), a]))
    /** @type {string | null} */
    let denied = null

    /**
     * @param {string | null} table
     * @param {(a: AuthorizeResult['access'][string]) => boolean} check
     * @param {string} what
     */
    const allow = (table, check, what) => {
      const entry = table ? access.get(table.toLowerCase()) : undefined
      if (entry && check(entry)) return c.SQLITE_OK
      denied ??= what
      return c.SQLITE_DENY
    }

    db.setAuthorizer((action, arg1, arg2, dbName) => {
      if (dbName && dbName !== 'main') {
        denied ??= `database ${dbName}`
        return c.SQLITE_DENY
      }
      switch (action) {
        case c.SQLITE_SELECT:
          return c.SQLITE_OK
        case c.SQLITE_READ:
          // An empty column name is a read of the row itself, e.g. count(*)
          return allow(arg1, a => !arg2 || a.read.includes(arg2.toLowerCase()), `read ${arg1}.${arg2}`)
        case c.SQLITE_INSERT:
          return allow(arg1, a => a.insert.length > 0, `insert into ${arg1}`)
        case c.SQLITE_UPDATE:
          return allow(arg1, a => a.update.includes(String(arg2).toLowerCase()), `update ${arg1}.${arg2}`)
        case c.SQLITE_DELETE:
          return allow(arg1, a => a.delete, `delete from ${arg1}`)
        case c.SQLITE_FUNCTION:
          if (functions.has(String(arg2).toLowerCase())) return c.SQLITE_OK
          denied ??= `function ${arg2}`
          return c.SQLITE_DENY
        default:
          denied ??= `action ${action}`
          return c.SQLITE_DENY
      }
    })
    try {
      db.prepare(result.sql)
    } catch (err) {
      if (denied) throw new PolicyError('VERIFY_FAILED', `SQLite denied: ${denied}`, { denied })
      throw new PolicyError('VERIFY_FAILED', `SQLite rejected the statement: ${err.message}`)
    } finally {
      db.setAuthorizer(null)
    }
  }
}

export {
  createVerifier
}
