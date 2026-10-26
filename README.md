# sql-policy

Let clients send their own SQL — and only reach what you allow.

`sql-policy` checks a client's SQLite statement against a **deny-by-default
policy** and rewrites it so it can only touch whitelisted tables, columns and
rows. You run the rewritten SQL with any SQLite driver: Cloudflare D1,
`node:sqlite`, better-sqlite3, sqlite-wasm, …

```js
import { createPolicy } from 'sql-policy'

const policy = createPolicy({
  tables: {
    game_items: { columns: ['id', 'name', 'description', 'rarity', 'icon_url'], select: true },
    player_inventory: {
      columns: ['id', 'item_id', 'quantity', 'equipped'],
      select: { where: ctx => ['user_id = ?', ctx.userId] },
      insert: { columns: ['item_id', 'quantity'], set: ctx => ({ user_id: ctx.userId }) },
      update: { columns: ['quantity', 'equipped'] },
      delete: true
    }
  },
  maxRows: 5000
})

const { sql, params } = policy.authorize(
  'SELECT g.name, i.quantity FROM player_inventory i JOIN game_items g ON g.id = i.item_id WHERE g.rarity = ?',
  ['legendary'],
  { userId: 1 }
)
const rows = await env.DB.prepare(sql).bind(...params).all()
```

`sql` is now:

```sql
SELECT `g`.`name`, `i`.`quantity`
FROM (SELECT `id`, `item_id`, `quantity`, `equipped` FROM `player_inventory` WHERE (`user_id` = ?2)) AS `i`
INNER JOIN (SELECT `id`, `name`, `description`, `rarity`, `icon_url` FROM `game_items`) AS `g` ON `g`.`id` = `i`.`item_id`
WHERE `g`.`rarity` = ?1 LIMIT 5000
```

and `params` is `['legendary', 1]`. The player only sees their own inventory,
and `user_id` is hidden but still set on every insert.

## Install

```sh
npm install sql-policy
```

ESM only. Node 22.5+ for `sql-policy/verify` (it uses `node:sqlite`). The main
export has no Node-specific code and runs in Workers, Deno, Bun and browsers.

## How it works

1. The statement is parsed into an AST ([node-sql-parser](https://github.com/taozhi8833998/node-sql-parser)).
   Only one statement is accepted.
2. Every node type, clause and function is checked against an allowlist.
   Anything unknown is rejected.
3. **Every table reference is replaced by a subquery** that selects only the
   whitelisted columns and applies the row filter:
   `users` → `(SELECT id, username, avatar_url, created_at FROM users WHERE …) AS users`.
   This one rewrite gives you:
   - `SELECT *` and `t.*` return exactly the whitelisted columns.
   - A hidden column cannot be used anywhere — not in WHERE, ON, ORDER BY,
     GROUP BY, HAVING, CASE or subqueries. SQLite answers "no such column",
     so nothing leaks through filtering or sorting.
   - The row filter holds everywhere: JOINs, subqueries, aggregates, UNION.
4. Writes are checked column by column, and the row filter is ANDed into the
   WHERE of UPDATE and DELETE.
5. The SQL you run is **generated from the checked AST**. The client's text is
   never executed. Identifiers are quoted with backticks, which SQLite never
   reads as strings, so a hidden column is an error in every SQLite build.

## Policy

```js
createPolicy({
  tables: { [name]: TablePolicy },
  functions: [...],   // SQL functions clients may call (default: DEFAULT_FUNCTIONS)
  maxRows: 5000,      // cap on LIMIT for SELECT (default: no cap)
  maxLength: 100000   // longest SQL accepted, in characters
})
```

Tables, columns and operations that are not listed do not exist for the client.

### TablePolicy

| Key | Value |
|---|---|
| `columns` | **Required.** Columns the client can see. Every other column is invisible. |
| `select` | `true`, `(ctx) => boolean` or `{ allow?, where? }` |
| `insert` | `true`, `(ctx) => boolean` or `{ allow?, columns?, set? }` |
| `update` | `true`, `(ctx) => boolean` or `{ allow?, columns?, set?, where? }` |
| `delete` | `true`, `(ctx) => boolean` or `{ allow?, where? }` |

- `allow(ctx)` returns whether the operation is allowed at all.
- `where(ctx)` is a row filter, written by you (it is trusted SQL). Return
  `'revoked = 0'`, `['user_id = ?', ctx.userId]`, `true`/`null` for
  every row, or `false` for no row. It may use columns that are not in
  `columns`.
- `columns` on insert/update lists the columns the client may write. It
  defaults to the table's `columns`, and must be a subset of them.
- `set(ctx)` returns values that are always written, e.g.
  `{ user_id: ctx.userId }`. They replace whatever the client sent, and may
  name columns the client cannot see.
- **UPDATE and DELETE inherit the SELECT row filter** unless they have their
  own `where`. A client cannot change rows it cannot see.

`ctx` is whatever you pass as the third argument to `authorize`, typically the
signed-in user.

## API

### `policy.authorize(sql, params?, ctx?)`

Returns `{ sql, params, kind, tables, access }` or throws a `PolicyError`.

- `sql` – the rewritten statement. Parameters are numbered (`?1`, `?2`, …):
  the client's first, then the policy's.
- `params` – the values to bind, in order.
- `kind` – `'select' | 'insert' | 'update' | 'delete'`.
- `tables` – the policy tables the statement touches.
- `access` – per table, the columns it may read, insert and update, and
  whether it may delete. Used by `verify`.

Clients use plain `?` parameters. `?NNN`, `:name`, `@name` and `$name` are
rejected.

### `policy.schema(ctx?)`

What a client with this `ctx` may do: `{ [table]: { columns, operations } }`.
Handy for API docs, or for creating a matching local database.

### `PolicyError`

| `code` | Meaning |
|---|---|
| `SYNTAX` | The SQL could not be parsed |
| `UNSUPPORTED` | A valid feature that is not allowed (PRAGMA, ATTACH, schema prefixes, several statements, …) |
| `TOO_LONG` | Longer than `maxLength` |
| `PARAMS` | The number of `?` does not match `params` |
| `TABLE_DENIED` | The table is not in the policy |
| `COLUMN_DENIED` | A write uses a column that is not allowed |
| `OPERATION_DENIED` | The operation is not allowed on that table for this `ctx` |
| `FUNCTION_DENIED` | The function is not in `functions` |
| `VERIFY_FAILED` | `verify` found access outside the policy |

`error.details` has the table, column, operation or function involved.
Reading a hidden column in a SELECT is not caught by `authorize` — the
rewritten SQL fails in SQLite with "no such column" instead.

### `sql-policy/verify`

An optional second opinion from SQLite itself. It prepares the rewritten
statement against an empty copy of your schema, with SQLite's authorizer
reporting every table, column and function it touches. Anything outside
`result.access` fails. This guards against the parser and SQLite reading the
same SQL differently.

```js
import { createVerifier } from 'sql-policy/verify'

const verify = createVerifier(schemaSql) // your CREATE TABLE statements
const result = policy.authorize(sql, params, ctx)
verify(result) // throws PolicyError VERIFY_FAILED
```

Requires `node:sqlite` (Node 22.5+). Pass `{ functions }` if you changed the
policy's function list.

## What is supported

- **SELECT** with JOIN (inner, left, cross, USING), subqueries anywhere,
  non-recursive CTEs, UNION / INTERSECT / EXCEPT, GROUP BY, HAVING, ORDER BY,
  LIMIT/OFFSET, DISTINCT, CASE, CAST, COLLATE, window functions with
  `PARTITION BY`, JSON operators.
- **INSERT INTO t (cols) VALUES (…), (…)**. Values must be literals or parameters.
- **UPDATE t SET col = value WHERE …**. Values must be literals or parameters.
  WHERE may use the table's visible columns and allowed functions, but no
  subqueries.
- **DELETE FROM t WHERE …**. Same rules for WHERE as UPDATE.

## Not supported

Rejected with `UNSUPPORTED` or `SYNTAX`:

- PRAGMA, ATTACH, DDL, transactions, `REPLACE`, `INSERT OR …`, `ON CONFLICT`,
  `RETURNING`, `INSERT … SELECT`, `UPDATE … FROM`.
- Schema-qualified names (`main.t`), table-valued functions
  (`json_each`, `pragma_*`), recursive CTEs (a CTE cannot see its own name).
- Named or numbered parameters.
- Parser limitations: `[bracketed]` identifiers, `NULLS FIRST/LAST`,
  `OVER (ORDER BY …)` without `PARTITION BY`, named `WINDOW` clauses,
  `VALUES` as a table, `LIMIT (subquery)`, `ESCAPE`, `MATCH`, `INDEXED BY`.
- `NATURAL JOIN` is misread by the parser as an alias named `natural`
  followed by an inner join without condition. It is not a security issue, but
  the result is a cross join, so avoid it.

## Security model

**What it protects:** tables, columns, rows and operations that are not in the
policy. This holds for any SQL that parses, including subqueries, CTEs that
shadow table names, aliases, comments, quoting tricks and `OR 1=1`.

**What it does not protect:**

- **Expensive queries.** Large cross joins can still be slow. Use `maxRows`,
  `maxLength`, timeouts in your database and rate limiting.
- **Your own filters.** `where` and `set` are trusted SQL. Never build them
  from client input other than through `?` parameters.
- **Inference through the columns you expose.** If a column is visible,
  clients can filter and aggregate on it.
- **Write-only tables.** With `update`/`delete` but no `select`, a client can
  still filter on visible columns in WHERE and learn from the number of
  changed rows.

## Testing

```sh
npm test
```

The tests use a small game backend (users, sessions, leaderboard, inventory,
items and config) and run every authorized statement against a real
`node:sqlite` database and through `verify`. Secrets such as
`users.password_hash`, `game_config.internal_value` and the whole
`auth_sessions` table stay outside the policy, and the tests check that no
query can reach them.

## License

MIT
