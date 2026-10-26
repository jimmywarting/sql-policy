import { test } from 'node:test'
import assert from 'node:assert/strict'
import { denied, plain, run } from './helpers.js'

test('SELECT * returns only whitelisted columns', () => {
  const { rows } = run("SELECT * FROM game_config WHERE key = 'maintenance_mode'")
  assert.deepEqual(plain(rows), [{ key: 'maintenance_mode', display_value: 'false' }])
})

test('alias.* returns only whitelisted columns', () => {
  const { rows } = run('SELECT u.* FROM users AS u ORDER BY u.id')
  assert.equal(rows.length, 2)
  assert.deepEqual(Object.keys(rows[0]), ['id', 'username', 'avatar_url', 'created_at'])
})

test('identifiers are case-insensitive like in SQLite', () => {
  const { rows } = run('SELECT USERNAME FROM Users WHERE ID = 2')
  assert.deepEqual(plain(rows), [{ username: 'StarFox' }])
})

test('JOIN between allowed tables', () => {
  const { rows, result } = run(`
    SELECT u.username, u.avatar_url, l.score
    FROM leaderboard l JOIN users u ON u.id = l.user_id
    ORDER BY l.rank`)
  assert.deepEqual(plain(rows), [
    { username: 'PixelKnight', avatar_url: '/avatars/knight.png', score: 15200 },
    { username: 'StarFox', avatar_url: '/avatars/fox.png', score: 12400 }
  ])
  assert.deepEqual(result.tables.sort(), ['leaderboard', 'users'])
})

test('LEFT JOIN, USING and comma joins', () => {
  assert.equal(run('SELECT * FROM users LEFT JOIN leaderboard ON leaderboard.user_id = users.id').rows.length, 2)
  assert.equal(run('SELECT users.username FROM users JOIN users AS u2 USING (id)').rows.length, 2)
  assert.equal(run('SELECT * FROM users, game_items').rows.length, 4)
})

test('JOIN against a table outside the policy is denied', () => {
  denied('SELECT * FROM users JOIN auth_sessions ON auth_sessions.user_id = users.id', 'TABLE_DENIED')
})

test('aggregates, GROUP BY and HAVING', () => {
  const { rows } = run(`
    SELECT season_id, count(*) AS n, max(score) AS top FROM leaderboard
    GROUP BY season_id HAVING count(*) > 1`)
  assert.deepEqual(plain(rows), [{ season_id: 1, n: 2, top: 15200 }])
})

test('subqueries in FROM, WHERE and the column list', () => {
  const { rows } = run(`
    SELECT username, (SELECT score FROM leaderboard WHERE leaderboard.user_id = x.id) AS score
    FROM (SELECT * FROM users) AS x
    WHERE id IN (SELECT user_id FROM leaderboard WHERE rank = 2)`)
  assert.deepEqual(plain(rows), [{ username: 'StarFox', score: 12400 }])
})

test('EXISTS and correlated subqueries', () => {
  const { rows } = run(`
    SELECT username FROM users u
    WHERE EXISTS (SELECT 1 FROM leaderboard l WHERE l.user_id = u.id AND l.score > 15000)`)
  assert.deepEqual(plain(rows), [{ username: 'PixelKnight' }])
})

test('CTEs, including one that refers to another', () => {
  const { rows } = run(`
    WITH leaders AS (SELECT * FROM leaderboard WHERE score > 13000),
         names AS (SELECT username FROM leaders)
    SELECT * FROM names`)
  assert.deepEqual(plain(rows), [{ username: 'PixelKnight' }])
})

test('UNION', () => {
  const { rows } = run('SELECT username AS name FROM users UNION ALL SELECT name FROM game_items ORDER BY 1')
  assert.deepEqual(rows.map(r => r.name), ['Dragon Gem', 'Iron Sword', 'PixelKnight', 'StarFox'])
})

test('window functions, CASE and CAST', () => {
  const { rows } = run(`
    SELECT username,
      rank() OVER (PARTITION BY season_id ORDER BY score DESC) AS place,
      CASE WHEN score > 13000 THEN 'gold' ELSE 'silver' END AS tier,
      CAST(score AS TEXT) AS points
    FROM leaderboard ORDER BY user_id`)
  assert.deepEqual(plain(rows), [
    { username: 'PixelKnight', place: 1, tier: 'gold', points: '15200' },
    { username: 'StarFox', place: 2, tier: 'silver', points: '12400' }
  ])
})

test('the row filter applies to plain selects', () => {
  const { rows } = run('SELECT item_id, quantity FROM player_inventory ORDER BY id')
  assert.deepEqual(plain(rows), [{ item_id: 1, quantity: 1 }, { item_id: 2, quantity: 3 }])
})

test('the row filter follows the ctx', () => {
  const { rows } = run('SELECT g.name, i.quantity FROM player_inventory i JOIN game_items g ON g.id = i.item_id', [], { uid: 2 })
  assert.deepEqual(plain(rows), [{ name: 'Iron Sword', quantity: 2 }])
})

test('the row filter applies in JOINs, subqueries, aggregates and UNION', () => {
  assert.deepEqual(plain(run('SELECT count(*) AS n FROM player_inventory').rows), [{ n: 2 }])
  assert.deepEqual(plain(run('SELECT i.id FROM users u JOIN player_inventory i ON 1 WHERE u.id = 2 ORDER BY i.id').rows), [{ id: 1 }, { id: 2 }])
  assert.deepEqual(plain(run('SELECT (SELECT count(*) FROM player_inventory) AS n').rows), [{ n: 2 }])
  assert.deepEqual(plain(run('SELECT id FROM player_inventory UNION SELECT id FROM player_inventory ORDER BY 1').rows), [{ id: 1 }, { id: 2 }])
  assert.deepEqual(plain(run('SELECT id FROM player_inventory WHERE id = 3 OR 1 = 1 ORDER BY id').rows), [{ id: 1 }, { id: 2 }])
})

test('a CTE named like a real table shadows it, as in SQLite', () => {
  const { rows } = run('WITH auth_sessions AS (SELECT 1 AS revoked) SELECT * FROM auth_sessions')
  assert.deepEqual(plain(rows), [{ revoked: 1 }])
})

test('literals and allowed functions', () => {
  const { rows } = run("SELECT lower('ABC') AS a, coalesce(NULL, 2) AS b, 'it''s' AS c, -1 AS d, X'00' AS e, NULL AS f")
  assert.equal(rows[0].a, 'abc')
  assert.equal(rows[0].b, 2)
  assert.equal(rows[0].c, "it's")
  assert.equal(rows[0].d, -1)
  assert.equal(rows[0].f, null)
})

test('a select with no table', () => {
  assert.deepEqual(plain(run('SELECT 1 + 1 AS two').rows), [{ two: 2 }])
})

test('the result names the kind and the tables', () => {
  const { result } = run('SELECT * FROM player_inventory')
  assert.equal(result.kind, 'select')
  assert.deepEqual(result.tables, ['player_inventory'])
  assert.deepEqual(result.access.player_inventory.read.sort(), ['equipped', 'id', 'item_id', 'quantity', 'user_id'])
})
