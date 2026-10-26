import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import { createPolicy, PolicyError } from '../src/index.js'
import { createVerifier } from '../src/verify.js'

const SCHEMA = `
  PRAGMA foreign_keys = ON;

  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    avatar_url TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE auth_sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE leaderboard (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    username TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    rank INTEGER NOT NULL,
    season_id INTEGER NOT NULL
  );

  CREATE TABLE player_inventory (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    item_id INTEGER NOT NULL REFERENCES game_items(id),
    quantity INTEGER NOT NULL DEFAULT 1,
    equipped INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE game_items (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    rarity TEXT NOT NULL,
    icon_url TEXT
  );

  CREATE TABLE game_config (
    key TEXT PRIMARY KEY,
    display_value TEXT,
    internal_value TEXT,
    environment TEXT NOT NULL
  );

  CREATE VIEW public_users AS SELECT id, username, avatar_url, created_at FROM users;
  CREATE VIEW public_game_items AS SELECT id, name, description, rarity, icon_url FROM game_items;
  CREATE VIEW public_leaderboard AS SELECT user_id, username, score, rank, season_id FROM leaderboard;
`

const DATA = `
  INSERT INTO users (id, username, avatar_url, email, password_hash) VALUES
    (1, 'PixelKnight', '/avatars/knight.png', 'knight@example.test', 'DEMO_HASH_001'),
    (2, 'StarFox', '/avatars/fox.png', 'fox@example.test', 'DEMO_HASH_002');
  INSERT INTO game_items (id, name, description, rarity, icon_url) VALUES
    (1, 'Iron Sword', 'A basic starter weapon', 'common', '/items/sword.png'),
    (2, 'Dragon Gem', 'A rare magical gem', 'legendary', '/items/gem.png');
  INSERT INTO player_inventory (user_id, item_id, quantity, equipped) VALUES (1, 1, 1, 1), (1, 2, 3, 0), (2, 1, 2, 0);
  INSERT INTO leaderboard (user_id, username, score, rank, season_id) VALUES (1, 'PixelKnight', 15200, 1, 1), (2, 'StarFox', 12400, 2, 1);
  INSERT INTO game_config (key, display_value, internal_value, environment) VALUES
    ('max_party_size', '4', '4', 'production'),
    ('maintenance_mode', 'false', 'internal-flag-001', 'production');
`

// auth_sessions and the views are not in the policy. users.email,
// users.password_hash, game_config.internal_value, game_config.environment and
// player_inventory.user_id are hidden.
const policy = createPolicy({
  maxRows: 100,
  tables: {
    users: { columns: ['id', 'username', 'avatar_url', 'created_at'], select: true },
    leaderboard: { columns: ['user_id', 'username', 'score', 'rank', 'season_id'], select: true },
    game_items: { columns: ['id', 'name', 'description', 'rarity', 'icon_url'], select: true },
    game_config: { columns: ['key', 'display_value'], select: true },
    player_inventory: {
      columns: ['id', 'item_id', 'quantity', 'equipped'],
      select: { where: ctx => ['user_id = ?', ctx.uid] },
      insert: { columns: ['item_id', 'quantity'], set: ctx => ({ user_id: ctx.uid }) },
      update: { columns: ['quantity', 'equipped'] },
      delete: true
    }
  }
})

const verify = createVerifier(SCHEMA)

/** A fresh database with the test data */
function setup () {
  const db = new DatabaseSync(':memory:')
  db.exec(SCHEMA)
  db.exec(DATA)
  return db
}

/**
 * Authorize, double check with SQLite's authorizer, then run.
 * @param {string} sql
 * @param {unknown[]} [params]
 * @param {any} [ctx]
 * @param {DatabaseSync} [db]
 */
function run (sql, params = [], ctx = { uid: 1 }, db = setup()) {
  const result = policy.authorize(sql, params, ctx)
  verify(result)
  const stmt = db.prepare(result.sql)
  const rows = result.kind === 'select' ? stmt.all(...result.params) : stmt.run(...result.params)
  return { result, rows, db }
}

/** Plain objects, so deepEqual ignores node:sqlite's null prototypes */
function plain (rows) {
  return rows.map(row => ({ ...row }))
}

/**
 * The statement must never reach data: either the policy rejects it, or
 * SQLite fails on the rewritten SQL. Returns the error.
 * @param {string} sql
 * @param {string} [code] Expected PolicyError code
 * @param {unknown[]} [params]
 */
function denied (sql, code, params = []) {
  let error
  try {
    run(sql, params)
  } catch (err) {
    error = err
  }
  assert.ok(error, `expected "${sql}" to be denied`)
  if (code) {
    assert.ok(error instanceof PolicyError, `expected PolicyError ${code}, got ${error.message}`)
    assert.equal(error.code, code, error.message)
  }
  return error
}

export {
  SCHEMA,
  denied,
  plain,
  policy,
  run,
  setup,
  verify
}
