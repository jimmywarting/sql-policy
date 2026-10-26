import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import { createPolicy } from '../src/index.js'
import { createVerifier } from '../src/verify.js'

test('an empty policy denies everything', () => {
  const policy = createPolicy({ tables: {} })
  assert.throws(() => policy.authorize('SELECT * FROM anything'), { code: 'TABLE_DENIED' })
})

test('a table with no operations denies everything', () => {
  const policy = createPolicy({ tables: { t: { columns: ['a'] } } })
  for (const sql of ['SELECT * FROM t', "INSERT INTO t (a) VALUES ('x')", "UPDATE t SET a = 'x'", 'DELETE FROM t']) {
    assert.throws(() => policy.authorize(sql), { code: 'OPERATION_DENIED' }, sql)
  }
})

test('select can be a function of the ctx', () => {
  const policy = createPolicy({ tables: { t: { columns: ['a'], select: ctx => ctx.ok } } })
  assert.throws(() => policy.authorize('SELECT * FROM t', [], { ok: false }), { code: 'OPERATION_DENIED' })
  assert.ok(policy.authorize('SELECT * FROM t', [], { ok: true }))
})

test('functions can be replaced', () => {
  const policy = createPolicy({ functions: ['upper'], tables: { t: { columns: ['a'], select: true } } })
  assert.ok(policy.authorize('SELECT upper(a) FROM t'))
  assert.throws(() => policy.authorize('SELECT lower(a) FROM t'), { code: 'FUNCTION_DENIED' })
})

test('schema() lists what the ctx may do', () => {
  const policy = createPolicy({
    tables: {
      a: { columns: ['id', 'name'], select: true, delete: ctx => ctx.admin },
      b: { columns: ['id'], select: ctx => ctx.admin },
      c: { columns: ['id'] }
    }
  })
  assert.deepEqual(policy.schema({ admin: false }), { a: { columns: ['id', 'name'], operations: ['select'] } })
  assert.deepEqual(policy.schema({ admin: true }), {
    a: { columns: ['id', 'name'], operations: ['select', 'delete'] },
    b: { columns: ['id'], operations: ['select'] }
  })
})

test('invalid configuration throws early', () => {
  assert.throws(() => createPolicy(), TypeError)
  assert.throws(() => createPolicy({ tables: { t: { columns: [] } } }), /non-empty/)
  assert.throws(() => createPolicy({ tables: { t: { columns: ['a b'] } } }), /invalid column/)
  assert.throws(() => createPolicy({ tables: { 'x;y': { columns: ['a'] } } }), /Invalid table/)
  assert.throws(() => createPolicy({ tables: { t: { columns: ['a'], update: { columns: ['b'] } } } }), /not in t.columns/)
  assert.throws(() => createPolicy({ maxRows: 0, tables: {} }), /maxRows/)
})

test('a bad policy filter is reported', () => {
  const policy = createPolicy({ tables: { t: { columns: ['a'], select: { where: () => 'a = = 1' } } } })
  assert.throws(() => policy.authorize('SELECT * FROM t'), { code: 'SYNTAX', message: /policy filter/ })
})

test("columns: '*' allows every column of the table", () => {
  const policy = createPolicy({
    tables: {
      t: {
        columns: '*',
        select: { where: () => 'a > 0' },
        insert: true,
        update: { columns: ['b'] },
        delete: true
      }
    }
  })
  const db = new DatabaseSync(':memory:')
  db.exec('CREATE TABLE t (a INTEGER, b TEXT, c TEXT); INSERT INTO t VALUES (0, \'x\', \'y\'), (1, \'z\', \'w\')')
  const verify = createVerifier('CREATE TABLE t (a INTEGER, b TEXT, c TEXT)')
  const run = (sql, params) => {
    const result = policy.authorize(sql, params)
    verify(result)
    return result
  }

  const select = run('SELECT * FROM t')
  assert.equal(select.sql, 'SELECT * FROM (SELECT * FROM `t` WHERE (`a` > 0)) AS `t`')
  assert.ok(select.access.t.read.includes('*'))
  assert.deepEqual(db.prepare(select.sql).all().map(r => ({ ...r })), [{ a: 1, b: 'z', c: 'w' }])

  run('INSERT INTO t (a, b, c) VALUES (?, ?, ?)', [2, 'b', 'c'])
  run("UPDATE t SET b = 'q' WHERE c = 'w'")
  assert.throws(() => policy.authorize("UPDATE t SET c = 'q'"), { code: 'COLUMN_DENIED' })
  run("DELETE FROM t WHERE c = 'w'")
  assert.deepEqual(policy.schema(), { t: { columns: '*', operations: ['select', 'insert', 'update', 'delete'] } })
})

test("'*' in insert/update columns needs columns: '*'", () => {
  assert.throws(() => createPolicy({ tables: { t: { columns: ['a'], insert: { columns: '*' } } } }), /cannot be '\*'/)
  assert.ok(createPolicy({ tables: { t: { columns: '*', insert: { columns: '*' } } } }))
})
