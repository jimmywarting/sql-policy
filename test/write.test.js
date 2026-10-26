import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPolicy } from '../src/index.js'
import { denied, plain, run, setup } from './helpers.js'

/** @param {import('node:sqlite').DatabaseSync} db */
const inventory = db => plain(db.prepare('SELECT id, user_id, item_id, quantity, equipped FROM player_inventory ORDER BY id').all())

test('INSERT with allowed columns, forced values filled in', () => {
  const { db, result } = run('INSERT INTO player_inventory (item_id, quantity) VALUES (?, 5), (1, 1)', [2])
  assert.equal(result.kind, 'insert')
  const added = inventory(db).slice(3)
  assert.deepEqual(added, [
    { id: 4, user_id: 1, item_id: 2, quantity: 5, equipped: 0 },
    { id: 5, user_id: 1, item_id: 1, quantity: 1, equipped: 0 }
  ])
})

test('INSERT cannot override a forced value', () => {
  denied('INSERT INTO player_inventory (item_id, user_id) VALUES (?, 2)', 'COLUMN_DENIED', [1])
})

test('a forced value replaces the client value when the column is insertable', () => {
  const policy = createPolicy({
    tables: { player_inventory: { columns: ['item_id', 'user_id'], insert: { set: () => ({ user_id: 1 }) } } }
  })
  const db = setup()
  const { sql, params } = policy.authorize('INSERT INTO player_inventory (item_id, user_id) VALUES (?, ?)', [1, 2])
  db.prepare(sql).run(...params)
  assert.equal(inventory(db).at(-1).user_id, 1)
})

test('INSERT of a non-insertable column is denied', () => {
  denied('INSERT INTO player_inventory (item_id, equipped) VALUES (1, 1)', 'COLUMN_DENIED')
  denied('INSERT INTO player_inventory (id, item_id) VALUES (99, ?)', 'COLUMN_DENIED', [1])
})

test('INSERT without a column list is denied', () => {
  denied('INSERT INTO player_inventory VALUES (9, 1, 1, 1, 0)', 'UNSUPPORTED')
})

test('INSERT ... SELECT is denied', () => {
  denied('INSERT INTO player_inventory (item_id) SELECT id FROM game_items', 'UNSUPPORTED')
})

test('INSERT OR REPLACE is denied', () => {
  denied('INSERT OR REPLACE INTO player_inventory (item_id) VALUES (1)', 'UNSUPPORTED')
})

test('INSERT values must be literals or parameters', () => {
  denied('INSERT INTO player_inventory (item_id) VALUES (abs(-1))', 'UNSUPPORTED')
  denied('INSERT INTO player_inventory (item_id) VALUES ((SELECT user_id FROM auth_sessions))', 'UNSUPPORTED')
})

test('INSERT into a read-only table is denied', () => {
  denied("INSERT INTO game_items (name, rarity) VALUES ('Free Gem', 'legendary')", 'OPERATION_DENIED')
})

test('UPDATE only touches rows inside the filter', () => {
  const { db } = run('UPDATE player_inventory SET quantity = ? WHERE id IN (1, 2, 3)', [99])
  assert.deepEqual(inventory(db).map(i => i.quantity), [99, 99, 2])
})

test('UPDATE with OR cannot escape the filter', () => {
  const { db } = run('UPDATE player_inventory SET quantity = 0 WHERE id = 3 OR 1 = 1')
  assert.deepEqual(inventory(db).map(i => i.quantity), [0, 0, 2])
})

test('UPDATE without WHERE still respects the filter', () => {
  const { db } = run('UPDATE player_inventory SET equipped = 1')
  assert.deepEqual(inventory(db).map(i => i.equipped), [1, 1, 0])
})

test('UPDATE of a non-updatable column is denied', () => {
  denied('UPDATE player_inventory SET user_id = 2 WHERE id = 1', 'COLUMN_DENIED')
  denied('UPDATE player_inventory SET item_id = 2', 'COLUMN_DENIED')
})

test('UPDATE WHERE on a hidden column is denied', () => {
  denied('UPDATE player_inventory SET quantity = 0 WHERE user_id = 2', 'COLUMN_DENIED')
  denied('UPDATE player_inventory SET quantity = 0 WHERE "user_id" = 2', 'COLUMN_DENIED')
})

test('UPDATE with a subquery is denied', () => {
  denied('UPDATE player_inventory SET quantity = 0 WHERE id IN (SELECT id FROM game_items)', 'UNSUPPORTED')
  denied("UPDATE player_inventory SET quantity = 0 WHERE EXISTS (SELECT 1 FROM users WHERE password_hash LIKE 'D%')", 'UNSUPPORTED')
})

test('UPDATE SET to an expression is denied', () => {
  denied('UPDATE player_inventory SET quantity = quantity + 1', 'UNSUPPORTED')
})

test('UPDATE ... RETURNING is denied', () => {
  denied('UPDATE player_inventory SET quantity = 0 RETURNING *', 'UNSUPPORTED')
})

test('UPDATE with an alias is denied', () => {
  denied('UPDATE player_inventory AS i SET quantity = 0', 'UNSUPPORTED')
})

test('DELETE only removes rows inside the filter', () => {
  const { db, result } = run('DELETE FROM player_inventory WHERE quantity > ?', [0])
  assert.equal(result.kind, 'delete')
  assert.deepEqual(inventory(db).map(i => i.id), [3])
})

test('DELETE on a table without delete permission is denied', () => {
  denied('DELETE FROM leaderboard', 'OPERATION_DENIED')
})

test('DELETE on a table outside the policy is denied', () => {
  denied('DELETE FROM auth_sessions', 'TABLE_DENIED')
})

test('operations can depend on the ctx', () => {
  const policy = createPolicy({
    tables: { leaderboard: { columns: ['user_id', 'score'], select: true, delete: ctx => ctx.admin === true } }
  })
  assert.throws(() => policy.authorize('DELETE FROM leaderboard', [], {}), { code: 'OPERATION_DENIED' })
  assert.ok(policy.authorize('DELETE FROM leaderboard', [], { admin: true }))
})

test('write rules can have their own row filter', () => {
  const policy = createPolicy({
    tables: {
      users: {
        columns: ['id', 'username', 'avatar_url'],
        select: true,
        update: { columns: ['avatar_url'], where: ctx => ['id = ?', ctx.uid] }
      }
    }
  })
  const db = setup()
  const { sql, params } = policy.authorize("UPDATE users SET avatar_url = '/avatars/new.png'", [], { uid: 2 })
  db.prepare(sql).run(...params)
  assert.deepEqual(db.prepare('SELECT avatar_url FROM users ORDER BY id').all().map(r => r.avatar_url), ['/avatars/knight.png', '/avatars/new.png'])
})

test('a filter returning false matches no rows', () => {
  const policy = createPolicy({
    tables: { game_items: { columns: ['id'], select: { where: () => false } } }
  })
  const db = setup()
  const { sql, params } = policy.authorize('SELECT * FROM game_items')
  assert.deepEqual(db.prepare(sql).all(...params), [])
})
