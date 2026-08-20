// enterprise-compliance — Host 插件集成冒烟测试
// 真实加载 lib/index.js（发布的构建产物），用 mock ctx 驱动 apply()，
// 覆盖：模块契约、6 个工具注册与执行、评分逻辑（全过 / 降级）、
// 审计事件入账（成功/失败/session 捕获）、遥测脱敏接线、settings 桥、timer、
// 策略可配置、阈值报警、评分历史、审计导出与过滤、数据导出/擦除、重启回载、文件扫描。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { name, inject, apply } from '../lib/index.js'

// 构造一个尽量贴近 Cordis 行为的 mock ctx：带 Guard 语义——
// 只有 inject 声明的服务才能作为 ctx 属性直接访问，未声明的访问抛错，
// 与真实 Cordis 运行时一致（防止 inject 声明与 apply 用法脱节再翻车）。
// 可选 overrides.scopeGet 让 settings.register 返回自定义持久化数据（模拟重启回载）。
function makeCtx(overrides = {}) {
  const registered = []   // settings.register 调用记录
  const updates = []      // settingsScope.update patch 记录
  const intervals = []    // timer.interval 调用记录
  const tools = []        // ctx.tools.register 记录
  const emitted = []      // ctx.emit 事件记录
  const events = new Map()
  const injected = new Set(inject) // 从模块实际导出同步

  const services = {
    tools: { register(t) { tools.push(t) } },
    sandboxPolicy: { defaultMode: 'workspace-write', workspaceRoot: 'C:/ws' },
    approval: {},
    sessionPersistence: {},
    credentials: {},
    sessionTelemetry: { sharing: 'off' },
    settings: {
      register(ns, schema, opts) {
        registered.push({ ns, schema, opts })
        return {
          get: () => (overrides.scopeGet !== undefined ? overrides.scopeGet : {}),
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

  const base = {
    get(n) { return services[n] },
    on(ev, h) { events.set(ev, h) },
    effect(fn) { return fn() }, // 立即执行以完成一次性注册（timer/effect 类）
    emit(ev, data) { emitted.push({ ev, data }) },
  }
  const ctx = new Proxy(base, {
    get(target, prop) {
      if (typeof prop === 'symbol') return Reflect.get(target, prop)
      if (Reflect.has(target, prop)) return Reflect.get(target, prop)
      if (injected.has(prop)) return services[prop]
      throw new Error(`cannot get property "${String(prop)}" without inject`)
    },
  })
  return { ctx, services, registered, updates, intervals, tools, events, emitted }
}

const toolNames = (tools) => tools.map((t) => t.name)
const findTool = (tools, n) => tools.find((t) => t.name === n)
const ALL_TOOLS = ['compliance_report', 'compliance_redact', 'compliance_audit', 'compliance_scan', 'compliance_data_export', 'compliance_data_erase']

test('模块契约：name / inject / apply 导出正确', () => {
  assert.equal(name, 'enterprise-compliance')
  assert.deepEqual(inject, ['tools', 'settings'])
  assert.equal(typeof apply, 'function')
})

test('Guard 语义：未在 inject 声明的 ctx 属性访问抛错，声明的可用', () => {
  const { ctx } = makeCtx()
  assert.throws(() => ctx.undeclaredThing, /without inject/)
  assert.equal(typeof ctx.tools.register, 'function') // inject 声明的 tools
  assert.equal(typeof ctx.settings.register, 'function') // inject 声明的 settings
})

test('apply 注册 6 个工具，且元数据完整', () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  assert.deepEqual(toolNames(tools), ALL_TOOLS)
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

test('compliance_report：json 导出结构化报告，markdown 导出表格，含历史趋势', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const j = await findTool(tools, 'compliance_report').execute({ format: 'json', history: true })
  const parsed = JSON.parse(j)
  assert.equal(parsed.report.score, 100)
  assert.equal(parsed.report.total, 7)
  assert.equal(parsed.report.items.length, 7)
  assert.ok(Array.isArray(parsed.history), 'history: true 应附带历史')
  const md = await findTool(tools, 'compliance_report').execute({ format: 'markdown' })
  assert.ok(md.includes('# 企业合规报告'), 'markdown 应含标题: ' + md)
  assert.ok(md.includes('| 检查项 | 状态 | 说明 |'), 'markdown 应含表格头: ' + md)
})

test('评分历史：连续调用记录历史（同分 60s 内去重）并持久化到 settings patch', async () => {
  const { ctx, tools, updates } = makeCtx()
  const realNow = Date.now
  let t = 1000000
  Date.now = () => t
  try {
    apply(ctx)
    await findTool(tools, 'compliance_report').execute({}) // 记录第 1 条
    t += 61000
    await findTool(tools, 'compliance_report').execute({}) // 记录第 2 条
    const last = updates[updates.length - 1].patch
    assert.equal(last.history.length, 2, '应持久化 2 条历史: ' + JSON.stringify(last.history))
    assert.equal(last.history[0].score, 100)
    // 同分且 60s 内再调 → 不重复记录
    const n = updates[updates.length - 1].patch.history.length
    await findTool(tools, 'compliance_report').execute({})
    assert.equal(updates[updates.length - 1].patch.history.length, n, '60s 内同分不应新增历史')
  } finally {
    Date.now = realNow
  }
})

test('策略可配置：关闭 approval 检查后 total=6 且不再出现该检查项', async () => {
  const { ctx, tools } = makeCtx({ scopeGet: { policy: { checks: { approval: false } } } })
  apply(ctx)
  const out = await findTool(tools, 'compliance_report').execute({})
  assert.ok(out.includes('通过 6/6'), '应 6/6，实际: ' + out)
  assert.ok(!out.includes('CC6.2'), '不应包含已关闭的检查项，实际: ' + out)
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

test('compliance_redact：rules 参数仅启用指定规则', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const out = await findTool(tools, 'compliance_redact').execute({ text: 'a@b.com 13800138000', rules: ['phone'] })
  assert.ok(out.includes('[phone]'), '应脱敏手机号: ' + out)
  assert.ok(out.includes('a@b.com'), '未启用 email 规则时应保留邮箱: ' + out)
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

test('compliance_audit：json/csv 导出与 tool/session 过滤', async () => {
  const { ctx, tools, events } = makeCtx()
  apply(ctx)
  events.get('tools/result')({ name: 'shell', args: { x: 1 }, agent: { session: { id: 's-1' } } }, { ok: true })
  events.get('tools/result')({ name: 'read', args: { p: '/a' } }, { ok: false, error: 'denied' })
  const j = await findTool(tools, 'compliance_audit').execute({ format: 'json' })
  const arr = JSON.parse(j)
  assert.equal(arr.length, 2)
  assert.equal(arr[0].tool, 'read') // 最新在前
  assert.equal(arr[0].error, 'denied')
  const csv = await findTool(tools, 'compliance_audit').execute({ format: 'csv' })
  assert.ok(csv.startsWith('time,tool,ok,error,sessionId'), 'csv 应有表头: ' + csv.slice(0, 40))
  const onlyShell = JSON.parse(await findTool(tools, 'compliance_audit').execute({ tool: 'shell', format: 'json' }))
  assert.equal(onlyShell.length, 1)
  assert.equal(onlyShell[0].tool, 'shell')
  const onlySession = JSON.parse(await findTool(tools, 'compliance_audit').execute({ sessionId: 's-1', format: 'json' }))
  assert.equal(onlySession.length, 1)
  const sinceOnly = JSON.parse(await findTool(tools, 'compliance_audit').execute({ since: Date.now() + 100000, format: 'json' }))
  assert.equal(sinceOnly.length, 0)
})

test('阈值报警：评分跌破阈值触发事件并写入 lastAlert，恢复后清零', async () => {
  const { ctx, services, events, intervals, updates, emitted } = makeCtx()
  const realNow = Date.now
  let t = 1000000
  Date.now = () => t
  try {
    apply(ctx) // 全过 → 100 分，不报警
    // 运行时降级 → 71 分 < 阈值 100
    services.approval = undefined
    services.sandboxPolicy = { defaultMode: 'danger-full-access', workspaceRoot: 'C:/ws' }
    t += 5000
    const iv = intervals.find((i) => i.ms === 5000)
    iv.fn()
    assert.ok(emitted.some((e) => e.ev === 'enterprise-compliance/alert'), '应发出 alert 事件: ' + JSON.stringify(emitted))
    const last = updates[updates.length - 1].patch
    assert.ok(last.lastAlert && last.lastAlert.detail, 'lastAlert 应写入: ' + JSON.stringify(last.lastAlert))
    assert.equal(last.lastAlert.score, 71)
    // 恢复 → 再次 tick → lastAlert 清零
    services.approval = {}
    services.sandboxPolicy = { defaultMode: 'workspace-write', workspaceRoot: 'C:/ws' }
    t += 5000
    iv.fn()
    const after = updates[updates.length - 1].patch
    assert.equal(after.lastAlert.detail, '', '恢复后 lastAlert 应清零: ' + JSON.stringify(after.lastAlert))
  } finally {
    Date.now = realNow
  }
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
  assert.ok(Array.isArray(patch.audit), 'patch 应含持久化审计')
  assert.ok(Array.isArray(patch.history), 'patch 应含历史')
  assert.ok(patch.policy && typeof patch.policy === 'object', 'patch 应含策略')
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
  assert.deepEqual(empty.audit, [], 'audit 应默认空数组')
  assert.deepEqual(empty.history, [], 'history 应默认空数组')
  assert.equal(empty.policy.alertThreshold, 100, '策略默认报警阈值应为 100')
  assert.equal(empty.policy.checks.approval, true, '检查项默认开启')
  assert.equal(empty.policy.rules.email, true, '规则默认开启')
  assert.equal(empty.lastAlert.detail, '', 'lastAlert 默认空')
})

test('重启回载：settings 持久化数据在 apply 时恢复审计/历史/策略', async () => {
  const { ctx, tools, emitted } = makeCtx({
    scopeGet: {
      audit: [{ time: 111, tool: 'old', ok: true, sessionId: 'x' }],
      history: [{ time: 111, score: 86, passed: 6, total: 7 }],
      policy: { alertThreshold: 80 },
    },
  })
  apply(ctx)
  const out = await findTool(tools, 'compliance_audit').execute({})
  assert.ok(out.includes('old'), '回载的审计应可见，实际: ' + out)
  assert.ok(out.includes('OK'), '回载审计应含状态')
  // 回载策略生效：阈值 80，当前 100 分 → 不报警
  assert.ok(!emitted.some((e) => e.ev === 'enterprise-compliance/alert'), '高分不应报警')
})

test('compliance_data_export：导出插件采集数据（Art.20 可携带权）', async () => {
  const { ctx, tools, events } = makeCtx()
  apply(ctx)
  events.get('tools/result')({ name: 'shell', args: { x: 1 } }, { ok: true })
  const out = await findTool(tools, 'compliance_data_export').execute({})
  const parsed = JSON.parse(out)
  assert.equal(parsed.provider, '@xiaobanli/dsh-enterprise-compliance')
  assert.ok(Array.isArray(parsed.data.audit), '应导出审计')
  assert.equal(parsed.data.audit.length, 1)
  assert.ok(parsed.data.audit[0].tool === 'shell')
})

test('compliance_data_erase：confirm 必填（框架校验），确认后清空审计/历史/报警（Art.17 删除权）', async () => {
  const { ctx, tools, events } = makeCtx()
  apply(ctx)
  events.get('tools/result')({ name: 'shell', args: { x: 1 } }, { ok: true })
  // confirm 声明为 required → 缺参由 dsh-tools 强制校验抛错（比软拒绝更严格，防止误触发销毁）
  await assert.rejects(() => findTool(tools, 'compliance_data_erase').execute({}), /confirm/, '缺 confirm 应抛 ToolArgsError')
  const ok = await findTool(tools, 'compliance_data_erase').execute({ confirm: true })
  assert.ok(ok.includes('已擦除'), '确认后应擦除: ' + ok)
  const out = await findTool(tools, 'compliance_audit').execute({})
  assert.equal(out, '（暂无审计记录）', '擦除后审计应清空')
})

test('compliance_scan：扫描真实文件发现敏感信息（allowOutside）', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises')
  const { join } = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const base = fileURLToPath(new URL('../', import.meta.url))
  const dir = await mkdtemp(join(base, '.scan-test-'))
  const f = join(dir, 'secret.txt')
  await writeFile(f, '联系 alice@example.com 或 key sk-abcdefghijklmnopqrstuvwxyz123456')
  try {
    const out = await findTool(tools, 'compliance_scan').execute({ path: f, allowOutside: true })
    assert.ok(out.includes('secret.txt'), '应包含文件名: ' + out)
    assert.ok(out.includes('emailx1'), '应含邮箱命中: ' + out)
    assert.ok(out.includes('apikeyx1'), '应含 api-key 命中: ' + out)
    assert.ok(!out.includes('alice@example.com'), '样例应已脱敏: ' + out)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('compliance_scan：默认拒绝扫描工作区之外路径', async () => {
  const { ctx, tools } = makeCtx()
  apply(ctx)
  const out = await findTool(tools, 'compliance_scan').execute({ path: 'C:/outside-everything/secret.txt' })
  assert.ok(out.includes('工作区之外'), '应拒绝工作区外路径: ' + out)
})

test('缺服务健壮性：无 settings/timer/sandboxPolicy 等 → apply 不抛错、工具仍可用', async () => {
  const { ctx, tools } = makeCtx({ services: { settings: undefined, timer: undefined, sandboxPolicy: undefined, approval: undefined, credentials: undefined, sessionPersistence: undefined, sessionTelemetry: undefined } })
  apply(ctx) // 不应抛错
  assert.deepEqual(toolNames(tools), ALL_TOOLS)
  const out = await findTool(tools, 'compliance_report').execute({})
  assert.ok(out.includes('沙箱=unknown'), '缺服务时应标记 unknown，实际: ' + out)
})
