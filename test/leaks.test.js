import { test } from 'node:test'
import assert from 'node:assert/strict'
import { denied, plain, run } from './helpers.js'

// users.email, users.password_hash, game_config.internal_value and
// player_inventory.user_id exist in the database but not in the policy. None
// of these may run, or they would leak something through filtering, sorting
// or grouping.
const HIDDEN_COLUMN = [
  ['column list', 'SELECT password_hash FROM users'],
  ['qualified', 'SELECT u.email FROM users u'],
  ['double quoted', 'SELECT "password_hash" FROM users'],
  ['backticks', 'SELECT `email` FROM users'],
  ['WHERE', "SELECT id FROM users WHERE email LIKE 'knight%'"],
  ['ON', "SELECT l.score FROM leaderboard l JOIN users u ON u.email = 'knight@example.test'"],
  ['ORDER BY', 'SELECT id FROM users ORDER BY password_hash'],
  ['GROUP BY', 'SELECT count(*) FROM game_config GROUP BY environment'],
  ['HAVING', "SELECT key FROM game_config GROUP BY key HAVING max(internal_value) > ''"],
  ['subquery', 'SELECT (SELECT max(password_hash) FROM users) AS x'],
  ['correlated subquery', "SELECT user_id FROM leaderboard l WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = l.user_id AND u.email LIKE 'k%')"],
  ['CASE', "SELECT CASE WHEN internal_value = 'x' THEN 1 END FROM game_config"],
  ['function argument', 'SELECT length(password_hash) FROM users'],
  ['window', 'SELECT row_number() OVER (PARTITION BY environment ORDER BY key) FROM game_config'],
  ['CTE', 'WITH x AS (SELECT email FROM users) SELECT * FROM x'],
  ['derived table', 'SELECT * FROM (SELECT internal_value FROM game_config)'],
  ['UNION', 'SELECT username FROM users UNION SELECT email FROM users'],
  ['row filter column', 'SELECT user_id FROM player_inventory'],
  ['rowid', 'SELECT rowid FROM users']
]

for (const [where, sql] of HIDDEN_COLUMN) {
  test(`hidden column in ${where} is never readable`, () => {
    const error = denied(sql)
    assert.match(error.message, /no such column|not allowed|denied/i)
  })
}

const MALICIOUS = [
  ['sqlite_master', 'SELECT * FROM sqlite_master', 'TABLE_DENIED'],
  ['sqlite_schema', 'SELECT sql FROM sqlite_schema', 'TABLE_DENIED'],
  ['schema prefix', 'SELECT * FROM main.users', 'UNSUPPORTED'],
  ['temp prefix', 'SELECT * FROM temp.users', 'UNSUPPORTED'],
  ['table-valued function', "SELECT * FROM pragma_table_info('users')", 'UNSUPPORTED'],
  ['json_each', "SELECT * FROM json_each('[1]')", 'UNSUPPORTED'],
  ['PRAGMA', 'PRAGMA table_info(users)', 'SYNTAX'],
  ['ATTACH', "ATTACH DATABASE 'x.db' AS x", 'UNSUPPORTED'],
  ['DROP', 'DROP TABLE users', 'UNSUPPORTED'],
  ['CREATE', 'CREATE TABLE x (a)', 'UNSUPPORTED'],
  ['two statements', 'SELECT 1; DELETE FROM users', 'UNSUPPORTED'],
  ['statement after comment', 'SELECT 1 /* x */; SELECT * FROM auth_sessions', 'UNSUPPORTED'],
  ['denied function', "SELECT load_extension('x')", 'FUNCTION_DENIED'],
  ['randomblob', 'SELECT randomblob(1000000000)', 'FUNCTION_DENIED'],
  ['printf', "SELECT printf('%.*c', 1000000000, 'x')", 'FUNCTION_DENIED'],
  ['sqlite_version', 'SELECT sqlite_version()', 'FUNCTION_DENIED'],
  ['reserved prefix', 'SELECT 1 AS __sp_p0', 'UNSUPPORTED'],
  ['named parameter', 'SELECT * FROM users WHERE id = :id', 'UNSUPPORTED'],
  ['dollar parameter', 'SELECT * FROM users WHERE id = $id', 'UNSUPPORTED'],
  ['numbered parameter', 'SELECT * FROM users WHERE id = ?1', 'UNSUPPORTED']
]

for (const [what, sql, code] of MALICIOUS) {
  test(`rejects ${what}`, () => {
    denied(sql, code)
  })
}

test('a view outside the policy is denied like any table', () => {
  denied('SELECT * FROM public_users', 'TABLE_DENIED')
})

test('a CTE cannot refer to itself, so recursion is impossible', () => {
  // Without its own name in scope, "c" inside the body is a table, and there
  // is no such table in the policy
  denied('WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c', 'TABLE_DENIED')
})

test('a CTE named like a denied table does not unlock the real table', () => {
  denied('WITH auth_sessions AS (SELECT * FROM auth_sessions) SELECT * FROM auth_sessions', 'TABLE_DENIED')
})

test('a CTE in a subquery is not visible outside it', () => {
  denied('SELECT * FROM (WITH auth_sessions AS (SELECT 1 AS token_hash) SELECT * FROM auth_sessions), auth_sessions', 'TABLE_DENIED')
})

test('an alias named like a denied table is harmless', () => {
  const { rows } = run('SELECT auth_sessions.username FROM users AS auth_sessions WHERE auth_sessions.id = 1')
  assert.deepEqual(plain(rows), [{ username: 'PixelKnight' }])
})

test('a ? inside a string or comment is not a parameter', () => {
  const { rows } = run("SELECT '?' AS q -- ?\n, id FROM users WHERE id = ? /* ? */", [1])
  assert.deepEqual(plain(rows), [{ q: '?', id: 1 }])
})

test('rows outside the filter cannot be reached through OR', () => {
  const { rows } = run('SELECT id FROM player_inventory WHERE 1 OR id = 3 ORDER BY id')
  assert.deepEqual(plain(rows), [{ id: 1 }, { id: 2 }])
})

test('IN with a bare table name is never read as a table', () => {
  denied('SELECT id FROM users WHERE id IN auth_sessions')
  denied('SELECT id FROM users WHERE id IN (auth_sessions)')
})

test('identifiers are never double-quoted, so a hidden column cannot become a string', () => {
  // SQLite builds that allow double-quoted strings read "password_hash" as
  // 'password_hash' when there is no such column. Backticks have no fallback.
  const { result } = run('SELECT id FROM users')
  assert.doesNotMatch(result.sql, /"/)
  const error = denied('SELECT "password_hash" FROM users')
  assert.match(error.message, /no such column/)
})

test('quotes inside strings and aliases survive the rewrite', () => {
  const { rows } = run('SELECT \'say "hi" `there`\' AS "a b", 1 AS "c`d"')
  assert.deepEqual(plain(rows), [{ 'a b': 'say "hi" `there`', 'c`d': 1 }])
})

test('JSON operators are allowed on visible columns', () => {
  const { rows } = run("SELECT '{\"a\":1}' ->> '$.a' AS a, username FROM users WHERE id = 1")
  assert.deepEqual(plain(rows), [{ a: 1, username: 'PixelKnight' }])
})
