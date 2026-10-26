import { PolicyError } from './errors.js'
import { authorize } from './rewrite.js'

/**
 * @typedef {string | [string, ...unknown[]] | boolean | null | undefined} WhereResult
 * A row filter: SQL for a WHERE clause with `?` parameters, given as
 * `'revoked = 0'` or `['user_id = ?', ctx.userId]`. `true`, `null` or
 * `undefined` means every row and `false` means no row.
 *
 * @typedef {(ctx: any) => WhereResult} WhereFn
 * @typedef {(ctx: any) => boolean} AllowFn
 *
 * @typedef {boolean | AllowFn | { allow?: AllowFn, where?: WhereFn }} SelectRule
 * @typedef {boolean | AllowFn | { allow?: AllowFn, columns?: string[], set?: (ctx: any) => Record<string, unknown> }} InsertRule
 * @typedef {boolean | AllowFn | { allow?: AllowFn, columns?: string[], set?: (ctx: any) => Record<string, unknown>, where?: WhereFn }} UpdateRule
 * @typedef {boolean | AllowFn | { allow?: AllowFn, where?: WhereFn }} DeleteRule
 *
 * @typedef {object} TablePolicy
 * @property {string[]} columns Columns that exist for clients. Everything else is invisible.
 * @property {SelectRule} [select]
 * @property {InsertRule} [insert]
 * @property {UpdateRule} [update]
 * @property {DeleteRule} [delete]
 *
 * @typedef {object} PolicyOptions
 * @property {Record<string, TablePolicy>} tables
 * @property {string[]} [functions] SQL functions clients may call
 * @property {number} [maxRows] Upper bound for LIMIT on SELECT
 * @property {number} [maxLength] Longest SQL text accepted, in characters
 */

// Functions that read nothing but their arguments and cannot blow up memory.
// printf/format, randomblob and zeroblob are left out on purpose.
const DEFAULT_FUNCTIONS = [
  'count', 'sum', 'total', 'avg', 'min', 'max', 'group_concat', 'string_agg',
  'abs', 'round', 'sign', 'length', 'lower', 'upper', 'substr', 'substring',
  'trim', 'ltrim', 'rtrim', 'replace', 'instr', 'hex', 'quote', 'typeof',
  'coalesce', 'ifnull', 'nullif', 'iif', 'like', 'glob',
  'date', 'time', 'datetime', 'julianday', 'unixepoch', 'strftime',
  'current_date', 'current_time', 'current_timestamp',
  'json', 'json_extract', 'json_array', 'json_object', 'json_array_length',
  'json_type', 'json_valid', 'json_group_array', 'json_group_object',
  'row_number', 'rank', 'dense_rank', 'percent_rank', 'cume_dist', 'ntile',
  'lag', 'lead', 'first_value', 'last_value', 'nth_value'
]

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
const OPERATIONS = ['select', 'insert', 'update', 'delete']

/**
 * @param {unknown} rule
 * @returns {null | { allow?: AllowFn, where?: WhereFn, columns?: string[], set?: Function }}
 */
function normalizeRule (rule) {
  if (rule === undefined || rule === false || rule === null) return null
  if (rule === true) return {}
  if (typeof rule === 'function') return { allow: /** @type {AllowFn} */ (rule) }
  if (typeof rule === 'object') return { ...rule }
  throw new TypeError(`Invalid rule: ${rule}`)
}

/**
 * @param {string} table
 * @param {string} label
 * @param {unknown} columns
 * @param {Set<string>} [within]
 */
function checkColumns (table, label, columns, within) {
  if (!Array.isArray(columns) || !columns.length) {
    throw new TypeError(`${table}.${label} must be a non-empty array of column names`)
  }
  for (const column of columns) {
    if (typeof column !== 'string' || !IDENTIFIER.test(column)) {
      throw new TypeError(`${table}.${label}: invalid column name ${column}`)
    }
    if (within && !within.has(column.toLowerCase())) {
      throw new TypeError(`${table}.${label}: ${column} is not in ${table}.columns`)
    }
  }
}

/**
 * @param {string} name
 * @param {TablePolicy} spec
 */
function normalizeTable (name, spec) {
  if (!IDENTIFIER.test(name)) throw new TypeError(`Invalid table name ${name}`)
  checkColumns(name, 'columns', spec?.columns)
  const columns = [...spec.columns]
  const known = new Set(columns.map(c => c.toLowerCase()))
  const table = { name, columns, known }
  for (const op of OPERATIONS) {
    const rule = normalizeRule(spec[op])
    if (rule && (op === 'insert' || op === 'update')) {
      if (rule.columns) checkColumns(name, `${op}.columns`, rule.columns, known)
      rule.columns = [...(rule.columns ?? columns)]
    }
    table[op] = rule
  }
  return table
}

/**
 * Create a policy. Tables, columns and operations that are not listed are denied.
 * @param {PolicyOptions} options
 */
function createPolicy (options) {
  const { tables, functions = DEFAULT_FUNCTIONS, maxRows, maxLength = 100_000 } = options ?? {}
  if (!tables || typeof tables !== 'object') throw new TypeError('options.tables is required')
  if (maxRows !== undefined && !(Number.isInteger(maxRows) && maxRows > 0)) {
    throw new TypeError('maxRows must be a positive integer')
  }

  const byName = new Map()
  for (const [name, spec] of Object.entries(tables)) {
    byName.set(name.toLowerCase(), normalizeTable(name, spec))
  }
  const config = {
    tables: byName,
    functions: new Set(functions.map(f => f.toLowerCase())),
    maxRows,
    maxLength
  }

  return {
    /**
     * Check a client's statement and rewrite it so it only reaches what the
     * policy allows. Run the returned `sql` with the returned `params`.
     * @param {string} sql
     * @param {unknown[]} [params]
     * @param {any} [ctx] Passed to every rule, e.g. the signed-in user
     */
    authorize (sql, params = [], ctx = {}) {
      if (typeof sql !== 'string') throw new TypeError('sql must be a string')
      if (!Array.isArray(params)) throw new TypeError('params must be an array')
      if (sql.length > config.maxLength) {
        throw new PolicyError('TOO_LONG', `SQL is longer than ${config.maxLength} characters`)
      }
      return authorize(config, sql, params, ctx)
    },

    /**
     * What a client with this ctx may do, table by table. Useful for docs and
     * for creating a matching local database.
     * @param {any} [ctx]
     */
    schema (ctx = {}) {
      /** @type {Record<string, { columns: string[], operations: string[] }>} */
      const out = {}
      for (const table of byName.values()) {
        const operations = OPERATIONS.filter(op => table[op] && (!table[op].allow || table[op].allow(ctx)))
        if (operations.length) out[table.name] = { columns: [...table.columns], operations }
      }
      return out
    }
  }
}

export {
  DEFAULT_FUNCTIONS,
  createPolicy
}
