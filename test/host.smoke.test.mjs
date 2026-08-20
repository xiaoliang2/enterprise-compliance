// enterprise-compliance — Host 插件集成冒烟测试
// 真实加载 lib/index.js（发布的构建产物），用 mock ctx 驱动 apply()，
// 覆盖：模块契约、3 个工具注册与执行、评分逻辑（全过 / 降级）、
// 审计事件入账（成功/失败/session 捕获）、遥测脱敏接线、settings 桥、timer。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { name, inject, apply } from '../lib/index.js'

// 构造一个尽量贴近 Cordis 行为的 mock ctx。
function makeCtx(overrides = {}) {
  const registered = []   // settings.register 调用记录
  const updates = []      // settingsScope.update patch 记录
  const intervals = []    // timer.interval 调用记录
  const tools = []        // ctx.tools.register 记录
  const events = new Map()

  const services = {
    sandboxPolicy: { defaultMode: 'workspace-write', workspaceRoot: 'C:/ws' },
    approval: {},
    sessionPersistence: {},
    credentials: {},
    sessionTelemetry: { sharing: 'off' },
    settings: {
      register(ns, schema, opts) {
        registered.push({ ns, schema, opts })
        return {
          get: () => ({}),
          watch: () => () => {},
          update: async (patch) => { updates.push({ ns, patch }) },
        }
      },
    },
    timer: {
      interval(fn, ms) { intervals.push({ fn, ms }); return () => {} },
    },
    ...(overrides.services || {}),
  }

  const ctx = {
    get(n) { return services[n] },
    on(ev, h) { events.set(ev, h) },
    effect(fn) { return fn() }, // 立即执行以完成一次性注册（timer/effect 类）
    tools: { register(t) { tools.push(t) } },
  }
  return { ctx, services, registered, updates, intervals, tools, events }
}

const toolNames = (tools) => tools.map((t) => t.name)
const findTool = (tools, n) => tools.find((t) => t.name === n)

test('模块契约：name / inject / apply 导出正确', () => {
  assert.equal(name, 'enterprise-compliance')
  assert.deepEqual(inject, ['tools', 'settings'])
  assert.equal(typeof apply, 'function')
})

test('apply 注册 3 个工具，且元数据完整', () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  assert.deepEqual(toolNames(tools), ['compliance_report', 'compliance_redact', 'compliance_audit'])
  for (const t of tools) {
    assert.equal(typeof t.execute, 'function')
    assert.equal(typeof t.description, 'string')
    assert.ok(t.description.length > 0)
    assert.ok(t.output && typeof t.output === 'object')
  }
})

test('compliance_report：全部服务挂载 → 100/100 通过 7/7', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const out = await findTool(tools, 'compliance_report').execute({})
  assert.equal(typeof out, 'string')
  assert.ok(out.includes('合规评分: 100/100'), '应输出满分，实际: ' + out)
  assert.ok(out.includes('通过 7/7'), '应 7/7 通过，实际: ' + out)
  assert.ok(out.includes('沙箱=workspace-write'), '应包含运行时事实，实际: ' + out)
})

test('compliance_report：危险沙箱 + 无审批 → 71/100，warn/fail 降级', async () => {
  const { ctx, tools } = makeCtx({
    services: {
      sandboxPolicy: { defaultMode: 'danger-full-access' },
      approval: undefined, // ctx.get('approval') → undefined
    },
  })
  apply(ctx)
  const out = await findTool(tools, 'compliance_report').execute({})
  assert.ok(out.includes('合规评分: 71/100'), '期望 71 分，实际: ' + out)
  assert.ok(out.includes('[WARN]'), '应包含 WARN 项，实际: ' + out)
  assert.ok(out.includes('[FAIL]'), '应包含 FAIL 项，实际: ' + out)
})

test('compliance_redact：邮箱+手机号被掩码，且命中统计正确', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const out = await findTool(tools, 'compliance_redact').execute({
    text: '联系 alice@example.com 或 13800138000',
  })
  assert.ok(out.includes('命中: emailx1, phonex1'), '命中统计错误: ' + out)
  assert.ok(out.includes('[email]') && out.includes('[phone]'))
  assert.ok(!out.includes('alice@example.com'), '邮箱未被掩码')
  assert.ok(!out.includes('13800138000'), '手机号未被掩码')
})

test('compliance_audit：初始为空 → 提示暂无记录', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const out = await findTool(tools, 'compliance_audit').execute({})
  assert.equal(out, '（暂无审计记录）')
})

test('tools/result 事件：成功调用入账（含工具名 / OK / session）', async () => {
  const { ctx, tools, events } = makeCtx()
  apply(ctx)
  events.get('tools/result')(
    { name: 'shell', args: { cmd: 'pwd' }, agent: { session: { id: 'sess-9' } } },
    { ok: true },
  )
  const out = await findTool(tools, 'compliance_audit').execute({})
  assert.ok(out.includes('shell'), '应含工具名，实际: ' + out)
  assert.ok(out.includes('OK'), '应标记 OK，实际: ' + out)
  assert.ok(out.includes('session=sess-9'), '应捕获 session，实际: ' + out)
})

test('tools/result 事件：失败调用记录 FAIL + 错误信息', async () => {
  const { ctx, tools, events } = makeCtx()
  apply(ctx)
  events.get('tools/result')({ name: 'fs-read', args: { path: '/x' } }, { ok: false, error: 'boom' })
  const out = await findTool(tools, 'compliance_audit').execute({})
  assert.ok(out.includes('fs-read'), '应含工具名，实际: ' + out)
  assert.ok(out.includes('FAIL (boom)'), '应含 FAIL+错误，实际: ' + out)
})

test('session-telemetry/record：敏感字段被脱敏（数据最小化接线）', () => {
  const { ctx, events } = makeCtx()
  apply(ctx)
  const record = {
    user: { email: 'alice@example.com' },
    tokens: ['sk-abcdefghijklmnopqrstuvwxyz123456'],
    nested: { ip: '1.2.3.4', phone: '13800138000' },
    plain: 'hello',
  }
  const out = events.get('session-telemetry/record')(null, () => record)
  assert.equal(out.user.email, '[email]')
  assert.ok(out.tokens[0].includes('[api-key]'), 'api key 未掩码: ' + out.tokens[0])
  assert.equal(out.nested.ip, '[ip]')
  assert.equal(out.nested.phone, '[phone]')
  assert.equal(out.plain, 'hello', '非敏感字段不应被改动')
})

test('settings 桥：register 命名空间正确、schema 有效、初始状态已发布、timer 5000ms', () => {
  const { ctx, registered, updates, intervals } = makeCtx()
  apply(ctx)
  assert.equal(registered.length, 1)
  assert.equal(registered[0].ns, 'enterprise-compliance')
  // schemastery schema 是"可调用对象"：直接 schema(value) 校验，并带标准 schema validate
  assert.equal(typeof registered[0].schema, 'function', '应传入 schemastery schema（可调用）')
  assert.equal(typeof registered[0].schema['~standard'].validate, 'function')
  assert.ok(updates.length >= 1, 'apply 末尾应发布一次初始状态')
  const patch = updates[0].patch
  assert.equal(patch.score, 100)
  assert.equal(patch.total, 7)
  assert.equal(patch.items.length, 7)
  assert.ok(Array.isArray(patch.recent))
  assert.ok(intervals.some((i) => i.ms === 5000), '应注册 5s 状态刷新定时器')
})

test('定时刷新：审计入账发布到 settings（含 session），无变化不重复写盘', () => {
  const { ctx, events, intervals, updates } = makeCtx()
  const realNow = Date.now
  let t = 1000000
  Date.now = () => t
  try {
    apply(ctx) // 初始发布一次
    const before = updates.length
    events.get('tools/result')(
      { name: 'web', args: { q: 'x' }, agent: { session: { id: 's-1' } } },
      { ok: true },
    )
    // 同一时刻 tools/result 内 publishStatus 被 2s 节流拦截 → 不产生新发布
    assert.equal(updates.length, before, '节流窗口内不应重复发布')

    const iv = intervals.find((i) => i.ms === 5000)
    assert.ok(iv, '应有 5s 刷新定时器')
    t += 5000 // 越过节流窗口
    iv.fn()
    const last = updates[updates.length - 1].patch
    assert.equal(last.auditCount, 1, '审计计数应入账')
    assert.equal(last.recent.length, 1)
    assert.equal(last.recent[0].tool, 'web')
    assert.equal(last.recent[0].ok, true)
    assert.equal(last.recent[0].sessionId, 's-1', 'sessionId 应保留')

    const countAfterFirst = updates.length
    t += 5000
    iv.fn() // 数据无变化 → change-guard 拦截，不写盘
    assert.equal(updates.length, countAfterFirst, '无变化时不应重复发布')
  } finally {
    Date.now = realNow
  }
})

test('StatusSchema 校验真实 patch：sessionId 缺省补空串、空对象回落默认值', () => {
  const { ctx, registered } = makeCtx()
  apply(ctx)
  const schema = registered[0].schema
  // 模拟真实 update() 时的 resolve：schema(mergeLayers(base, section))
  const resolved = schema({
    score: 86, passed: 6, total: 7, auditCount: 2,
    items: [{ id: 'sandbox', status: 'pass', control: 'CC6.1', detail: 'x' }],
    recent: [{ time: 1, tool: 't', ok: true }], // 无 sessionId
  })
  assert.equal(resolved.score, 86)
  assert.equal(resolved.items.length, 1)
  assert.equal(resolved.recent[0].sessionId, '', 'sessionId 应回落默认空串')
  // 空对象 → 全部默认值，校验不抛错（注册时即会以此形态 resolve）
  const empty = schema({})
  assert.equal(empty.score, 0)
  assert.equal(empty.total, 7)
  assert.deepEqual(empty.items, [])
  assert.deepEqual(empty.recent, [])
})

test('缺服务健壮性：无 settings/timer/sandboxPolicy 等 → apply 不抛错、工具仍可用', async () => {
  const { ctx, tools } = makeCtx({ services: { settings: undefined, timer: undefined, sandboxPolicy: undefined, approval: undefined, credentials: undefined, sessionPersistence: undefined, sessionTelemetry: undefined } })
  apply(ctx) // 不应抛错
  assert.deepEqual(toolNames(tools), ['compliance_report', 'compliance_redact', 'compliance_audit'])
  const out = await findTool(tools, 'compliance_report').execute({})
  assert.ok(out.includes('沙箱=unknown'), '缺服务时应标记 unknown，实际: ' + out)
})
