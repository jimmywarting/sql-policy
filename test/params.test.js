import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPolicy } from '../src/index.js'
import { denied, plain, policy, run } from './helpers.js'

test('user and policy parameters end up in the right order', () => {
  // The policy filter on player_inventory comes first in the rewritten SQL,
  // but the user's parameters still bind to ?1 and ?2
  const { rows, result } = run(`
    SELECT g.name, u.username AS who
    FROM player_inventory i JOIN game_items g ON g.id = i.item_id JOIN users u ON u.id = ?
    WHERE i.quantity = ?`, [2, 3])
  assert.deepEqual(plain(rows), [{ name: 'Dragon Gem', who: 'StarFox' }])
  assert.deepEqual(result.params, [2, 3, 1])
})

test('a table used twice gets its filter parameters twice', () => {
  const { rows, result } = run('SELECT a.id FROM player_inventory a JOIN player_inventory b ON a.id = b.id ORDER BY a.id')
  assert.deepEqual(plain(rows), [{ id: 1 }, { id: 2 }])
  assert.deepEqual(result.params, [1, 1])
})

test('wrong parameter count is rejected', () => {
  denied('SELECT * FROM users WHERE id = ?', 'PARAMS', [])
  denied('SELECT * FROM users', 'PARAMS', [1])
})

test('parameters in LIMIT and OFFSET', () => {
  const { rows } = run('SELECT id FROM users ORDER BY id LIMIT ? OFFSET ?', [1, 1])
  assert.deepEqual(plain(rows), [{ id: 2 }])
})

test('maxRows adds a LIMIT when there is none', () => {
  const { result } = run('SELECT * FROM users')
  assert.match(result.sql, /LIMIT 100$/)
})

test('maxRows lowers a LIMIT that is too high or negative', () => {
  assert.match(run('SELECT * FROM users LIMIT 5000').result.sql, /LIMIT 100$/)
  assert.match(run('SELECT * FROM users LIMIT -1').result.sql, /LIMIT 100$/)
  assert.match(run('SELECT * FROM users LIMIT 5').result.sql, /LIMIT 5$/)
})

test('maxRows caps a parameterised LIMIT', () => {
  const small = createPolicy({ maxRows: 2, tables: { users: { columns: ['id'], select: true } } })
  const { sql, params } = small.authorize('SELECT id FROM users LIMIT ?', [-1])
  assert.equal(params.length, 1)
  assert.match(sql, /CASE WHEN \?1 BETWEEN 0 AND 2 THEN \?1 ELSE 2 END/)
})

test('maxRows applies to the whole UNION', () => {
  assert.match(run('SELECT id FROM users UNION SELECT id FROM game_items').result.sql, /LIMIT 100$/)
})

test('maxRows keeps the offset in LIMIT offset, count', () => {
  const { rows } = run('SELECT id FROM users ORDER BY id LIMIT 1, 1000')
  assert.deepEqual(plain(rows), [{ id: 2 }])
})

test('SQL longer than maxLength is rejected', () => {
  assert.throws(() => policy.authorize('SELECT 1' + ' '.repeat(100_000)), { code: 'TOO_LONG' })
})
