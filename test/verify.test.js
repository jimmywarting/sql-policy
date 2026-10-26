import { test } from 'node:test'
import assert from 'node:assert/strict'
import { policy, verify } from './helpers.js'

/** Authorize, then tamper with the result as a buggy rewrite might */
function tampered (sql, change) {
  const result = policy.authorize(sql, [], { uid: 1 })
  return { ...result, ...change(result) }
}

test('passes what authorize produced', () => {
  verify(policy.authorize('SELECT * FROM users JOIN leaderboard ON leaderboard.user_id = users.id'))
  verify(policy.authorize('UPDATE player_inventory SET quantity = 2 WHERE id = 1', [], { uid: 1 }))
  verify(policy.authorize('INSERT INTO player_inventory (item_id) VALUES (1)', [], { uid: 1 }))
  verify(policy.authorize('DELETE FROM player_inventory', [], { uid: 1 }))
})

test('catches a read of a hidden column', () => {
  const result = tampered('SELECT * FROM users', () => ({ sql: 'SELECT password_hash FROM users' }))
  assert.throws(() => verify(result), { code: 'VERIFY_FAILED', message: /users\.password_hash/ })
})

test('catches a table outside the access list', () => {
  const result = tampered('SELECT * FROM users', () => ({ sql: 'SELECT * FROM auth_sessions' }))
  assert.throws(() => verify(result), { code: 'VERIFY_FAILED', message: /auth_sessions/ })
})

test('catches writes that were not authorized', () => {
  const update = tampered('UPDATE player_inventory SET quantity = 2', () => ({ sql: 'UPDATE player_inventory SET user_id = 2' }))
  assert.throws(() => verify(update), { code: 'VERIFY_FAILED', message: /user_id/ })
  const del = tampered('SELECT * FROM player_inventory', () => ({ sql: 'DELETE FROM player_inventory' }))
  assert.throws(() => verify(del), { code: 'VERIFY_FAILED', message: /delete/ })
})

test('catches functions outside the list', () => {
  const result = tampered('SELECT 1', () => ({ sql: 'SELECT randomblob(10)' }))
  assert.throws(() => verify(result), { code: 'VERIFY_FAILED', message: /randomblob/ })
})

test('catches pragmas and recursion', () => {
  assert.throws(() => verify(tampered('SELECT 1', () => ({ sql: "SELECT * FROM pragma_table_info('users')" }))), { code: 'VERIFY_FAILED' })
  assert.throws(() => verify(tampered('SELECT 1', () => ({ sql: 'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c' }))), { code: 'VERIFY_FAILED' })
})
