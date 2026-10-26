import nsp from 'node-sql-parser/build/sqlite.js'
import { PolicyError } from './errors.js'

const parser = new nsp.Parser()
const OPTIONS = { database: 'sqlite' }

// Prefix of the placeholders that stand in for `?` while parsing. User input
// may never contain it, so a placeholder always comes from markParams.
const RESERVED = '__sp_'

/**
 * The parser cannot read `?` everywhere (LIMIT ?) and cannot read `?NNN` at
 * all, so every `?` outside strings and comments becomes `:__sp_<kind><n>`.
 * @param {string} sql
 * @param {string} kind 'p' for user parameters, 'q' for policy parameters
 */
function markParams (sql, kind) {
  let out = ''
  let count = 0
  let i = 0
  while (i < sql.length) {
    const c = sql[i]
    let end = i + 1
    if (c === "'" || c === '"' || c === '`') {
      end = sql.indexOf(c, i + 1)
      while (end !== -1 && sql[end + 1] === c) end = sql.indexOf(c, end + 2)
      end = end === -1 ? sql.length : end + 1
    } else if (c === '[') {
      end = sql.indexOf(']', i)
      end = end === -1 ? sql.length : end + 1
    } else if (c === '-' && sql[i + 1] === '-') {
      end = sql.indexOf('\n', i)
      if (end === -1) end = sql.length
    } else if (c === '/' && sql[i + 1] === '*') {
      end = sql.indexOf('*/', i + 2)
      end = end === -1 ? sql.length : end + 2
    } else if (c === '?') {
      if (/[0-9]/.test(sql[i + 1] ?? '')) {
        throw new PolicyError('UNSUPPORTED', 'Numbered parameters (?NNN) are not supported, use ?')
      }
      out += ` :${RESERVED}${kind}${count++} `
      i++
      continue
    }
    out += sql.slice(i, end)
    i = end
  }
  return { text: out, count }
}

/**
 * Parse exactly one statement written by a client.
 * @param {string} sql
 */
function parseStatement (sql) {
  if (sql.toLowerCase().includes(RESERVED)) {
    throw new PolicyError('UNSUPPORTED', `Identifiers starting with ${RESERVED} are reserved`)
  }

  const { text, count } = markParams(sql, 'p')
  let ast

  try {
    ast = parser.astify(text, OPTIONS)
  } catch (err) {
    throw new PolicyError('SYNTAX', `Could not parse SQL: ${err.message}`)
  }

  if (Array.isArray(ast)) {
    if (ast.length !== 1) throw new PolicyError('UNSUPPORTED', 'Only one statement per query')
    ast = ast[0]
  }

  return { ast, paramCount: count }
}

/** @type {Map<string, object>} */
const fragments = new Map()

/**
 * Parse a trusted WHERE fragment from the policy into an expression AST.
 * The result is a fresh copy every time, so callers may mutate it.
 * @param {string} sql
 */
function parseFragment (sql) {
  let where = fragments.get(sql)
  if (!where) {
    const { text } = markParams(sql, 'q')
    try {
      where = parser.astify(`SELECT 1 WHERE (${text})`, OPTIONS).where
    } catch (err) {
      throw new PolicyError('SYNTAX', `Could not parse policy filter "${sql}": ${err.message}`)
    }
    fragments.set(sql, where)
  }
  return structuredClone(where)
}

/**
 * The parser quotes identifiers as "name". Builds of SQLite that still allow
 * double-quoted strings read "name" as the string 'name' when there is no
 * such column, so a hidden column would quietly turn into a constant. Backtick
 * quoting has no such fallback: a missing column is always an error.
 * @param {string} sql Output of sqlify, where only strings use single quotes
 */
function backtickIdentifiers (sql) {
  let out = ''
  let i = 0
  while (i < sql.length) {
    const c = sql[i]
    if (c !== "'" && c !== '"') {
      out += c
      i++
      continue
    }
    let end = sql.indexOf(c, i + 1)
    while (end !== -1 && sql[end + 1] === c) end = sql.indexOf(c, end + 2)
    if (end === -1) throw new PolicyError('SYNTAX', 'Unterminated quote in generated SQL')
    const token = sql.slice(i, end + 1)
    if (c === "'") {
      out += token
    } else {
      const name = token.slice(1, -1).replaceAll('""', '"')
      out += '`' + name.replaceAll('`', '``') + '`'
    }
    i = end + 1
  }
  return out
}

/** @param {object} ast */
function toSql (ast) {
  return backtickIdentifiers(parser.sqlify(ast, OPTIONS))
}

export {
  RESERVED,
  markParams,
  parseFragment,
  parseStatement,
  toSql
}
