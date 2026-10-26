import { PolicyError } from './errors.js'
import { parseFragment, parseStatement, RESERVED, toSql } from './parse.js'

// Node types that are plain values
const LITERALS = new Set(['number', 'single_quote_string', 'hex_string', 'bool', 'null'])

// Keys a SELECT node may carry with a value. Anything else is a feature we
// have not reviewed, so it is rejected.
const SELECT_KEYS = new Set([
  'type', 'with', 'options', 'distinct', 'columns', 'from', 'where', 'groupby',
  'having', 'orderby', 'limit', 'for_update', '_next', 'set_op', 'parentheses'
])
const FROM_KEYS = new Set(['db', 'table', 'as', 'join', 'on', 'using', 'expr'])

const USER_PARAM = new RegExp(`^${RESERVED}p(\\d+)$`)
const POLICY_PARAM = new RegExp(`^${RESERVED}q(\\d+)$`)

/**
 * @typedef {object} Config
 * @property {Map<string, any>} tables
 * @property {Set<string>} functions
 * @property {number} [maxRows]
 *
 * @typedef {object} State
 * @property {Config} config
 * @property {any} ctx
 * @property {unknown[]} params
 * @property {Map<string, { read: Set<string>, insert: Set<string>, update: Set<string>, delete: boolean }>} access
 *
 * @typedef {object} Scope
 * @property {Set<string>} ctes Lower-cased CTE names visible here
 * @property {null | { table: any, columns: Set<string> }} write Set while checking an UPDATE/DELETE WHERE
 */

/**
 * @param {string} message
 * @param {Record<string, unknown>} [details]
 */
const unsupported = (message, details) => new PolicyError('UNSUPPORTED', message, details)

/**
 * @param {State} st
 * @param {string} name
 */
function accessFor (st, name) {
  let entry = st.access.get(name)
  if (!entry) {
    entry = { read: new Set(), insert: new Set(), update: new Set(), delete: false }
    st.access.set(name, entry)
  }
  return entry
}

/**
 * @param {State} st
 * @param {unknown} value
 */
function pushParam (st, value) {
  st.params.push(value)
  return { type: 'origin', value: `?${st.params.length}` }
}

/**
 * @param {State} st
 * @param {string} name
 */
function lookupTable (st, name) {
  const table = st.config.tables.get(name.toLowerCase())
  if (!table) throw new PolicyError('TABLE_DENIED', `Table ${name} is not allowed`, { table: name })
  return table
}

/**
 * @param {State} st
 * @param {any} table
 * @param {'select' | 'insert' | 'update' | 'delete'} op
 */
function ruleFor (st, table, op) {
  const rule = table[op]
  if (!rule || (rule.allow && !rule.allow(st.ctx))) {
    throw new PolicyError('OPERATION_DENIED', `${op.toUpperCase()} on ${table.name} is not allowed`, { table: table.name, operation: op })
  }
  return rule
}

/**
 * Build the row filter for an operation, or null when every row is allowed.
 * UPDATE and DELETE fall back to the SELECT filter, so a client can never
 * change rows it cannot see unless the policy says so.
 * @param {State} st
 * @param {any} table
 * @param {'select' | 'update' | 'delete'} op
 */
function rowFilter (st, table, op) {
  const where = table[op]?.where ?? (op !== 'select' ? table.select?.where : undefined)
  if (!where) return null
  const result = where(st.ctx)
  if (result === undefined || result === null || result === true) return null
  if (result === false) return { type: 'number', value: 0 }
  const [sql, ...values] = typeof result === 'string' ? [result] : result
  if (typeof sql !== 'string') throw new TypeError(`${table.name}.${op}.where must return SQL text`)

  const ast = parseFragment(sql)
  const read = accessFor(st, table.name).read
  walk(ast, node => {
    if (node.type === 'param') {
      const match = POLICY_PARAM.exec(node.value)
      if (!match) throw new TypeError(`${table.name}.${op}.where: only ? parameters are supported`)
      if (+match[1] >= values.length) throw new TypeError(`${table.name}.${op}.where: missing parameter value`)
      Object.assign(node, pushParam(st, values[+match[1]]))
    } else if (node.type === 'column_ref' && typeof node.column === 'string') {
      read.add(node.column.toLowerCase())
    }
  })
  return ast
}

/**
 * Visit every object in a trusted AST.
 * @param {any} node
 * @param {(node: any) => void} fn
 */
function walk (node, fn) {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) return node.forEach(n => walk(n, fn))
  fn(node)
  for (const value of Object.values(node)) walk(value, fn)
}

/** @param {any} left @param {any} right */
function and (left, right) {
  if (!left) return right
  if (!right) return left
  // Parentheses keep `a OR b` from swallowing the policy filter
  return {
    type: 'binary_expr',
    operator: 'AND',
    left: { ...left, parentheses: true },
    right: { ...right, parentheses: true }
  }
}

/** @param {any} column */
function columnName (column) {
  if (typeof column === 'string') return column
  if (column?.expr?.type === 'default' || column?.expr?.type === 'backticks_quote_string') return column.expr.value
  throw unsupported('Unsupported column reference')
}

/**
 * Replace a table reference with a subquery that holds only the allowed
 * columns and rows. Every other check follows from this: SQLite itself
 * rejects any column that is not in the subquery, wherever it is used.
 * @param {State} st
 * @param {string} name
 * @param {string | null} alias
 */
function wrapTable (st, name, alias) {
  const table = lookupTable(st, name)
  ruleFor(st, table, 'select')
  const read = accessFor(st, table.name).read
  for (const column of table.columns) read.add(column.toLowerCase())
  return {
    expr: {
      ast: {
        type: 'select',
        with: null,
        options: null,
        distinct: null,
        columns: table.columns.map(column => ({ expr: { type: 'column_ref', table: null, column }, as: null })),
        from: [{ db: null, table: table.name, as: null }],
        where: rowFilter(st, table, 'select'),
        groupby: null,
        having: null,
        orderby: null,
        limit: null
      },
      parentheses: true
    },
    as: alias ?? name
  }
}

/**
 * @param {State} st
 * @param {any} item
 * @param {Scope} scope
 */
function fromItem (st, item, scope) {
  for (const [key, value] of Object.entries(item)) {
    if (value != null && !FROM_KEYS.has(key)) throw unsupported(`Unsupported FROM clause (${key})`)
  }
  let out = item
  if (typeof item.table === 'string') {
    if (item.db) throw unsupported('Schema-qualified tables are not allowed')
    if (!scope.ctes.has(item.table.toLowerCase())) {
      out = { ...wrapTable(st, item.table, item.as), join: item.join, on: item.on, using: item.using }
    }
  } else if (item.expr?.ast) {
    select(st, item.expr.ast, scope)
  } else {
    throw unsupported('Only tables and subqueries may appear in FROM')
  }
  if (item.join && !/^(NATURAL )?((LEFT|RIGHT|FULL)( OUTER)?|INNER|CROSS)? ?JOIN$/i.test(item.join)) {
    throw unsupported(`Unsupported join ${item.join}`)
  }
  if (out.on) expr(st, out.on, scope)
  if (out.using) {
    for (const u of out.using) if (u?.type !== 'default') throw unsupported('Unsupported USING')
  }
  return out
}

/**
 * @param {State} st
 * @param {any} node
 * @param {Scope} scope
 */
function expr (st, node, scope) {
  if (node === null || node === undefined) return
  if (Array.isArray(node)) return node.forEach(n => expr(st, n, scope))

  // A subquery anywhere in an expression
  if (node.ast) {
    if (scope.write) throw unsupported('Subqueries are not allowed in UPDATE or DELETE')
    return select(st, node.ast, scope)
  }

  switch (node.type) {
    case 'double_quote_string':
      // SQLite reads "x" as a column when one exists, so check it as one
      Object.assign(node, { type: 'column_ref', table: null, column: node.value })
      delete node.value
      return expr(st, node, scope)

    case 'column_ref': {
      if (node.db || node.schema) throw unsupported('Schema-qualified columns are not allowed')
      if (scope.write) {
        const { table, columns } = scope.write
        const name = columnName(node.column)
        if (node.table && node.table.toLowerCase() !== table.name.toLowerCase()) {
          throw new PolicyError('TABLE_DENIED', `Unknown table ${node.table}`, { table: node.table })
        }
        if (!columns.has(name.toLowerCase())) {
          throw new PolicyError('COLUMN_DENIED', `Column ${name} is not allowed`, { table: table.name, column: name })
        }
      }
      return
    }

    case 'param': {
      const match = USER_PARAM.exec(node.value)
      if (!match) throw unsupported('Named parameters are not supported, use ?')
      Object.assign(node, { type: 'origin', value: `?${+match[1] + 1}` })
      return
    }

    case 'star':
      return

    case 'binary_expr':
      expr(st, node.left, scope)
      expr(st, node.right, scope)
      return

    case 'unary_expr':
      return expr(st, node.expr, scope)

    case 'expr_list':
      return expr(st, node.value, scope)

    case 'case':
      expr(st, node.expr, scope)
      for (const arm of node.args) {
        if (arm.type !== 'when' && arm.type !== 'else') throw unsupported('Unsupported CASE')
        expr(st, arm.cond, scope)
        expr(st, arm.result, scope)
      }
      return

    case 'cast':
      return expr(st, node.expr, scope)

    case 'function':
    case 'aggr_func': {
      const parts = node.type === 'function' ? node.name?.name : [{ value: node.name }]
      if (!Array.isArray(parts) || parts.length !== 1) throw unsupported('Schema-qualified functions are not allowed')
      const name = String(parts[0].value).toLowerCase()
      if (name !== 'exists' && !st.config.functions.has(name)) {
        throw new PolicyError('FUNCTION_DENIED', `Function ${name} is not allowed`, { function: name })
      }
      if (node.filter) throw unsupported('FILTER is not supported')
      if (node.type === 'function') {
        expr(st, node.args, scope)
      } else {
        expr(st, node.args?.expr, scope)
        expr(st, node.args?.orderby?.map(o => o.expr), scope)
      }
      if (node.over) {
        if (scope.write) throw unsupported('Window functions are not allowed in UPDATE or DELETE')
        if (node.over.type === 'window' || typeof node.over === 'string') throw unsupported('Named windows are not supported')
        expr(st, node.over.partitionby?.map(p => p.expr), scope)
        expr(st, node.over.orderby?.map(o => o.expr), scope)
      }
      return
    }

    default:
      if (LITERALS.has(node.type)) return
      throw unsupported(`Unsupported expression (${node.type})`, { node: node.type })
  }
}

/**
 * Check and rewrite a SELECT, including UNION/INTERSECT/EXCEPT parts and CTEs.
 * @param {State} st
 * @param {any} node
 * @param {Scope} outer
 */
function select (st, node, outer) {
  const scope = { ctes: new Set(outer.ctes), write: outer.write }
  if (node.with) {
    for (const cte of node.with) {
      const name = cte.name?.value
      if (typeof name !== 'string' || !cte.stmt?.ast) throw unsupported('Unsupported WITH')
      // A CTE cannot see itself, so its own name in its body is the real
      // table. That rules out recursion: the name gets wrapped like any table.
      select(st, cte.stmt.ast, scope)
      scope.ctes.add(name.toLowerCase())
    }
  }
  for (let part = node; part; part = part._next) {
    if (part.type !== 'select') throw unsupported(`Unsupported statement (${part.type})`)
    for (const [key, value] of Object.entries(part)) {
      if (value != null && !SELECT_KEYS.has(key)) throw unsupported(`Unsupported SELECT clause (${key})`)
    }
    if (part !== node && part.with) throw unsupported('WITH is only allowed at the start')
    if (part.options || part.for_update) throw unsupported('Unsupported SELECT options')
    if (part.distinct && part.distinct !== 'DISTINCT') throw unsupported(`Unsupported ${part.distinct}`)
    if (part.from) part.from = part.from.map(item => fromItem(st, item, scope))
    if (part.columns === '*') part.columns = [{ expr: { type: 'column_ref', table: null, column: '*' }, as: null }]
    expr(st, part.columns?.map(c => c.expr), scope)
    expr(st, part.where, scope)
    expr(st, part.groupby?.columns, scope)
    expr(st, part.having, scope)
    expr(st, part.orderby?.map(o => o.expr), scope)
    expr(st, part.limit?.value, scope)
  }
}

/**
 * Cap the number of rows a SELECT returns. A negative LIMIT means no limit in
 * SQLite, so anything outside 0..maxRows becomes maxRows.
 * @param {any} node
 * @param {number} maxRows
 */
function capRows (node, maxRows) {
  let last = node
  while (last._next) last = last._next
  const max = { type: 'number', value: maxRows }
  if (!last.limit?.value?.length) {
    last.limit = { seperator: '', value: [max] }
    return
  }
  // `LIMIT offset, count` keeps the count second
  const i = last.limit.seperator === ',' ? 1 : 0
  const count = last.limit.value[i]
  if (count.type === 'number') {
    if (!(count.value >= 0 && count.value <= maxRows)) last.limit.value[i] = max
    return
  }
  last.limit.value[i] = {
    type: 'case',
    expr: null,
    args: [
      {
        type: 'when',
        cond: { type: 'binary_expr', operator: 'BETWEEN', left: count, right: { type: 'expr_list', value: [{ type: 'number', value: 0 }, max] } },
        result: structuredClone(count)
      },
      { type: 'else', result: max }
    ],
    parentheses: true
  }
}

/**
 * Resolve the single target table of INSERT, UPDATE or DELETE.
 * @param {State} st
 * @param {any[]} list
 */
function target (st, list) {
  if (!Array.isArray(list) || list.length !== 1) throw unsupported('Only one target table is allowed')
  const [item] = list
  if (typeof item.table !== 'string') throw unsupported('Unsupported target table')
  if (item.db) throw unsupported('Schema-qualified tables are not allowed')
  if (item.as) throw unsupported('Aliases are not allowed on the target table')
  return lookupTable(st, item.table)
}

/**
 * Values written by a client must be plain literals or parameters.
 * @param {State} st
 * @param {any} node
 * @param {Scope} scope
 */
function writeValue (st, node, scope) {
  const plain = LITERALS.has(node?.type) || node?.type === 'param' ||
    (node?.type === 'unary_expr' && node.operator === '-' && node.expr?.type === 'number')
  if (!plain) throw unsupported('Only literals and parameters may be written')
  expr(st, node, scope)
}

/**
 * Forced column values from a rule's `set`.
 * @param {State} st
 * @param {any} table
 * @param {any} rule
 * @returns {[string, unknown][]}
 */
function forcedValues (st, table, rule) {
  const entries = Object.entries(rule.set?.(st.ctx) ?? {})
  for (const [column] of entries) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) throw new TypeError(`${table.name}: invalid column in set: ${column}`)
  }
  return entries
}

/**
 * @param {State} st
 * @param {any} ast
 */
function insert (st, ast) {
  for (const key of ['or', 'with', 'returning', 'on_duplicate_update', 'partition', 'set']) {
    if (ast[key]) throw unsupported(`Unsupported INSERT clause (${key})`)
  }
  if (ast.prefix && ast.prefix.toLowerCase() !== 'into') throw unsupported(`Unsupported INSERT ${ast.prefix}`)
  const table = target(st, ast.table)
  const rule = ruleFor(st, table, 'insert')
  if (!Array.isArray(ast.columns) || !ast.columns.length) throw unsupported('INSERT needs a column list')
  if (ast.values?.type !== 'values') throw unsupported('Only INSERT ... VALUES is supported')

  const allowed = new Set(rule.columns.map(c => c.toLowerCase()))
  const columns = ast.columns.map(columnName)
  const seen = new Set()
  for (const column of columns) {
    const lower = column.toLowerCase()
    if (!allowed.has(lower)) throw new PolicyError('COLUMN_DENIED', `Column ${column} may not be inserted`, { table: table.name, column })
    if (seen.has(lower)) throw unsupported(`Column ${column} is listed twice`)
    seen.add(lower)
  }

  const scope = { ctes: new Set(), write: null }
  for (const row of ast.values.values) {
    if (row.type !== 'expr_list' || row.value.length !== columns.length) {
      throw new PolicyError('SYNTAX', 'Each row needs one value per column')
    }
    for (const value of row.value) writeValue(st, value, scope)
  }

  for (const [column, value] of forcedValues(st, table, rule)) {
    let i = columns.findIndex(c => c.toLowerCase() === column.toLowerCase())
    if (i === -1) i = columns.push(column) - 1
    const param = pushParam(st, value)
    for (const row of ast.values.values) row.value[i] = { ...param }
  }
  ast.columns = columns
  const access = accessFor(st, table.name).insert
  for (const column of columns) access.add(column.toLowerCase())
}

/**
 * @param {State} st
 * @param {any} ast
 */
function update (st, ast) {
  for (const key of ['with', 'from', 'returning', 'orderby', 'limit', 'or']) {
    if (ast[key]) throw unsupported(`Unsupported UPDATE clause (${key})`)
  }
  const table = target(st, ast.table)
  const rule = ruleFor(st, table, 'update')
  const allowed = new Set(rule.columns.map(c => c.toLowerCase()))
  const scope = { ctes: new Set(), write: { table, columns: table.known } }
  const access = accessFor(st, table.name)

  for (const item of ast.set) {
    const column = columnName(item.column)
    if (item.table && item.table.toLowerCase() !== table.name.toLowerCase()) throw unsupported('Unsupported SET target')
    if (!allowed.has(column.toLowerCase())) throw new PolicyError('COLUMN_DENIED', `Column ${column} may not be updated`, { table: table.name, column })
    writeValue(st, item.value, scope)
  }
  for (const [column, value] of forcedValues(st, table, rule)) {
    const existing = ast.set.find(s => columnName(s.column).toLowerCase() === column.toLowerCase())
    const param = pushParam(st, value)
    if (existing) existing.value = param
    else ast.set.push({ column, value: param, table: null })
  }
  for (const item of ast.set) access.update.add(columnName(item.column).toLowerCase())

  expr(st, ast.where, scope)
  for (const column of table.known) access.read.add(column)
  ast.where = and(ast.where, rowFilter(st, table, 'update'))
}

/**
 * @param {State} st
 * @param {any} ast
 */
function remove (st, ast) {
  for (const key of ['with', 'using', 'returning', 'orderby', 'limit']) {
    if (ast[key]) throw unsupported(`Unsupported DELETE clause (${key})`)
  }
  const table = target(st, ast.from)
  if (ast.table && (ast.table.length !== 1 || ast.table[0].table !== ast.from[0].table)) {
    throw unsupported('Only one target table is allowed')
  }
  ruleFor(st, table, 'delete')
  const scope = { ctes: new Set(), write: { table, columns: table.known } }
  expr(st, ast.where, scope)
  const access = accessFor(st, table.name)
  for (const column of table.known) access.read.add(column)
  access.delete = true
  ast.where = and(ast.where, rowFilter(st, table, 'delete'))
}

/**
 * @param {Config} config
 * @param {string} sql
 * @param {unknown[]} params
 * @param {any} ctx
 */
function authorize (config, sql, params, ctx) {
  const { ast, paramCount } = parseStatement(sql)
  if (paramCount !== params.length) {
    throw new PolicyError('PARAMS', `Expected ${paramCount} parameters, got ${params.length}`)
  }

  /** @type {State} */
  const st = { config, ctx, params: [...params], access: new Map() }
  const kind = ast.type
  switch (kind) {
    case 'select':
      select(st, ast, { ctes: new Set(), write: null })
      if (config.maxRows) capRows(ast, config.maxRows)
      break
    case 'insert':
      insert(st, ast)
      break
    case 'update':
      update(st, ast)
      break
    case 'delete':
      remove(st, ast)
      break
    default:
      throw unsupported(`Unsupported statement (${kind})`)
  }

  const out = toSql(ast)
  // Every placeholder must have been turned into ?N by now
  if (out.includes(`:${RESERVED}`)) throw unsupported('Parameter in an unsupported position')

  /** @type {Record<string, { read: string[], insert: string[], update: string[], delete: boolean }>} */
  const access = {}
  for (const [name, a] of st.access) {
    access[name] = { read: [...a.read], insert: [...a.insert], update: [...a.update], delete: a.delete }
  }
  return {
    sql: out,
    params: st.params,
    kind: /** @type {'select' | 'insert' | 'update' | 'delete'} */ (kind),
    tables: Object.keys(access),
    access
  }
}

export {
  authorize
}
