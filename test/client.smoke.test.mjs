// enterprise-compliance — Client bundle 冒烟测试
// 真实加载 client/client.js（发布产物），校验：
//   - __ModuleLoader__.load 契约（id + factory）
//   - factory 返回 { name, inject, apply }，inject 服务正确
//   - apply 接线：locale 注册 / settingsScope 绑定 / settings.section 侧边栏页注册
//   - ComplianceCard 组件用真实 React.createElement 渲染出预期结构
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const src = readFileSync(new URL('../client/client.js', import.meta.url), 'utf8')

// 捕获 __ModuleLoader__.load 的入参
let loaded = null
const sandboxWindow = { __ModuleLoader__: { load(def) { loaded = def } } }
// 在提供 window 的上下文中执行产物
new Function('window', src)(sandboxWindow)

test('产物契约：__ModuleLoader__.load({ id, factory })', () => {
  assert.ok(loaded, '应调用 window.__ModuleLoader__.load')
  assert.equal(loaded.id, '@xiaobanli/dsh-enterprise-compliance')
  assert.equal(typeof loaded.factory, 'function')
})

test('factory 返回插件对象：name / inject / apply', () => {
  const plugin = loaded.factory(require) // require('react') 走本地 node_modules
  assert.equal(plugin.name, 'enterprise-compliance')
  assert.deepEqual(plugin.inject, ['slots', 'locale', 'settingsScope'])
  assert.equal(typeof plugin.apply, 'function')
})

test('apply 接线：locale 注册、settingsScope 绑定、slot 注入', () => {
  const calls = { localeRegister: [], localeBind: [], settingsBind: [], slotsInject: [], slotsRegister: [] }
  const scope = {
    subscribe() { return () => {} },
    getSnapshot() { return { value: {} } },
  }
  const ctx = {
    effect(fn) { return fn() }, // 立即执行以建立 locale 注册
    locale: {
      register(ns, dicts) { calls.localeRegister.push({ ns, dicts }); return () => {} },
      bind(ns) { calls.localeBind.push(ns); return (key) => '[' + key + ']' },
    },
    settingsScope: {
      bind(opts) { calls.settingsBind.push(opts); return scope },
    },
    slots: {
      inject(slot, fn) { calls.slotsInject.push({ slot, fn }) },
      register(desc, Component) { calls.slotsRegister.push({ desc, Component }); return () => {} },
    },
  }
  const plugin = loaded.factory(require)
  plugin.apply(ctx)

  // locale 注册
  assert.equal(calls.localeRegister.length, 1)
  assert.equal(calls.localeRegister[0].ns, 'enterprise-compliance')
  assert.ok(calls.localeRegister[0].dicts.zh['card.title'])
  assert.ok(calls.localeRegister[0].dicts.en['card.title'])
  // settingsScope 绑定命名空间
  assert.deepEqual(calls.settingsBind, [{ namespace: 'enterprise-compliance' }])
  // slot 注入发生在 settings.section（设置侧边栏独立页面）
  assert.equal(calls.slotsInject.length, 1)
  assert.equal(calls.slotsInject[0].slot, 'settings.section')
  // 触发注入回调 → slots.register 注册页面
  calls.slotsInject[0].fn()
  assert.equal(calls.slotsRegister.length, 1)
  const reg = calls.slotsRegister[0]
  assert.equal(reg.desc.id, 'enterprise-compliance')
  assert.equal(reg.desc.order, 30)
  // 侧边栏标签来自 locale 绑定
  assert.equal(typeof reg.desc.label, 'function')
  assert.equal(reg.desc.label(), '[card.title]')
  // 页面组件存在
  assert.equal(typeof reg.Component, 'function')
})

test('ComplianceCard 渲染逻辑：真实 createElement + 受控 store，输出预期结构', () => {
  // 真实浏览器是客户端渲染，useSyncExternalStore(sub, get) 两参合法；
  // 这里用受控 store（同步返回快照）直接调用组件函数，验证渲染逻辑。
  const ReactReal = require('react')
  const shim = { ...ReactReal, useSyncExternalStore: (_sub, getSnap) => getSnap() }
  const plugin = loaded.factory((mod) => (mod === 'react' ? shim : require(mod)))

  let reg = null
  const snap = { value: {
    score: 86, passed: 6, total: 7, auditCount: 2,
    items: [{ id: 'sandbox', status: 'pass', control: 'CC6.1' }, { id: 'approval', status: 'fail', control: 'CC6.2' }],
    recent: [{ time: 1, tool: 'web', ok: true, sessionId: 's-1' }, { time: 2, tool: 'fs', ok: false }],
  } }
  const scope = { subscribe() { return () => {} }, getSnapshot() { return snap } }
  const ctx = {
    effect(fn) { return fn() },
    locale: {
      register() { return () => {} },
      bind() { return (key) => ({ 'card.title': 'T', 'card.passed': 'P', 'card.score': 'S', 'card.items': 'I', 'card.recent': 'R', 'card.tools': 'M', 'card.empty': 'E', 'card.noAudit': 'N', 'card.pass': 'PASS', 'card.warn': 'WARN', 'card.fail': 'FAIL' }[key] || key) },
    },
    settingsScope: { bind() { return scope } },
    slots: {
      inject(_s, fn) { fn() },
      register(desc, Component) { reg = { desc, Component } },
    },
  }
  plugin.apply(ctx)
  const wrapperEl = reg.Component({}) // 页面组件闭包使用 apply 时绑定的 t/scope
  // 手动渲染函数组件：createElement(ComplianceCard, props) → 调用组件函数得到元素树
  const el = typeof wrapperEl.type === 'function' ? wrapperEl.type(wrapperEl.props) : wrapperEl
  const texts = []
  ;(function walk(node) {
    if (node == null) return
    if (typeof node === 'string' || typeof node === 'number') { texts.push(String(node)); return }
    if (Array.isArray(node)) { node.forEach(walk); return }
    if (node && node.props) {
      const c = node.props.children
      if (c == null) return
      walk(c)
    }
  })(el)
  const joined = texts.join('|')
  assert.ok(joined.includes('86/100'), '应显示评分，实际: ' + joined)
  assert.ok(joined.includes('6/7'), '应显示通过数，实际: ' + joined)
  assert.ok(joined.includes('CC6.1') && joined.includes('CC6.2'), '应显示检查项，实际: ' + joined)
  assert.ok(joined.includes('PASS') && joined.includes('FAIL'), '应显示状态徽标，实际: ' + joined)
  assert.ok(joined.includes('web') && joined.includes('fs'), '应显示审计工具名，实际: ' + joined)
  assert.ok(joined.includes('s-1'), '应显示会话号，实际: ' + joined)
})
