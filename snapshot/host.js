// ============================================================================
// enterprise-compliance — Host 端源码（compl-1 / pkg-1 导出快照）
// ----------------------------------------------------------------------------
// 本文件内容是 cordis_define 的 code.host 参数原值：一个返回 Cordis Plugin
// 的纯 JavaScript 函数体（非 TypeScript、无 import/require 变换）。
// 重新注册时把本文件完整内容作为 code.host 传入即可。
// ============================================================================
return {
  apply(ctx) {
    // ---------------- 敏感信息脱敏引擎 ----------------
    const RULES = [
      { id: 'email', label: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
      { id: 'phone', label: 'phone', re: /\b1[3-9]\d{9}\b/g },
      { id: 'idcard', label: 'id-card', re: /\b\d{17}[\dXx]\b/g },
      { id: 'bankcard', label: 'bank-card', re: /\b\d{16,19}\b/g },
      { id: 'apikey', label: 'api-key', re: /\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,}|xox[bap]-[A-Za-z0-9-]{10,})\b/g },
      { id: 'jwt', label: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
      { id: 'bearer', label: 'bearer', re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/gi },
      { id: 'privatekey', label: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----\n[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
      { id: 'ip', label: 'ip', re: /\b\d{1,3}(?:\.\d{1,3}){3}\b/g },
    ]

    function redact(text) {
      if (typeof text !== 'string') return { text: String(text), findings: [] }
      let out = text
      const counts = {}
      for (const rule of RULES) {
        rule.re.lastIndex = 0
        out = out.replace(rule.re, () => {
          counts[rule.id] = (counts[rule.id] || 0) + 1
          return '[' + rule.label + ']'
        })
      }
      const findings = Object.keys(counts).map((id) => ({ type: id, count: counts[id] }))
      return { text: out, findings }
    }

    function redactDeep(value, depth) {
      if (depth > 8) return value
      if (typeof value === 'string') return redact(value).text
      if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1))
      if (value && typeof value === 'object') {
        const out = {}
        for (const key of Object.keys(value)) {
          try { out[key] = redactDeep(value[key], depth + 1) } catch (e) { out[key] = value[key] }
        }
        return out
      }
      return value
    }

    // ---------------- 操作审计日志 ----------------
    const AUDIT_CAP = 500
    const audit = []

    function pushAudit(entry) {
      audit.push(entry)
      if (audit.length > AUDIT_CAP) audit.splice(0, audit.length - AUDIT_CAP)
    }

    ctx.on('tools/result', (exec, result) => {
      try {
        const tool = exec && typeof exec.name === 'string' ? exec.name : 'unknown'
        const args = exec && exec.args !== undefined ? redactDeep(exec.args, 0) : null
        const ok = !!(result && result.ok !== false)
        const error = result && result.error ? String(result.error) : null
        let sessionId = null
        try {
          const agent = exec && exec.agent
          if (agent && agent.session && typeof agent.session.id === 'string') sessionId = agent.session.id
        } catch (e) { /* ignore */ }
        pushAudit({ time: Date.now(), tool, ok, error, args, sessionId })
      } catch (e) { /* 审计不得打断工具流水线 */ }
    })

    // ---------------- 遥测导出脱敏（GDPR 数据最小化） ----------------
    ctx.on('session-telemetry/record', (record, next) => {
      const base = next()
      try {
        return base && typeof base === 'object' ? redactDeep(base, 0) : base
      } catch (e) {
        return base
      }
    })

    // ---------------- SOC2/GDPR 合规自检 ----------------
    function complianceReport() {
      const sandbox = ctx.get('sandboxPolicy')
      const approval = ctx.get('approval')
      const persistence = ctx.get('sessionPersistence')
      const creds = ctx.get('credentials')
      const telemetry = ctx.get('sessionTelemetry')
      const defaultMode = sandbox ? String(sandbox.defaultMode) : 'unknown'
      const sharing = telemetry ? String(telemetry.sharing) : 'not-configured'
      const workspaceRoot = sandbox && typeof sandbox.workspaceRoot === 'string' ? sandbox.workspaceRoot : null
      const sandboxSafe = defaultMode !== 'danger-full-access'
      const items = [
        { id: 'sandbox', standard: 'SOC2', control: 'CC6.1 文件沙箱隔离', status: sandboxSafe ? 'pass' : 'warn', detail: '默认沙箱模式: ' + defaultMode },
        { id: 'approval', standard: 'SOC2', control: 'CC6.2 权限审批', status: approval ? 'pass' : 'fail', detail: approval ? '审批服务已挂载' : '未检测到审批服务' },
        { id: 'audit', standard: 'SOC2', control: 'CC7.2 操作审计', status: 'pass', detail: '审计采集已启用，当前 ' + audit.length + ' 条' },
        { id: 'redaction', standard: 'SOC2/GDPR', control: 'CC7.3 / Art.25 敏感数据脱敏', status: 'pass', detail: '脱敏引擎已启用（' + RULES.length + ' 类规则）' },
        { id: 'credentials', standard: 'SOC2', control: 'CC6.6 凭证管理', status: creds ? 'pass' : 'warn', detail: creds ? '凭证服务已挂载' : '未检测到凭证服务' },
        { id: 'persistence', standard: 'SOC2', control: 'A1.2 持久化日志', status: persistence ? 'pass' : 'warn', detail: persistence ? '会话持久化已挂载' : '未检测到持久化' },
        { id: 'telemetry', standard: 'GDPR', control: 'Art.5 导出数据最小化', status: 'pass', detail: '遥测导出已脱敏，共享策略: ' + sharing },
      ]
      const passed = items.filter((i) => i.status === 'pass').length
      return {
        score: items.length ? Math.round((passed / items.length) * 100) : 0,
        passed,
        total: items.length,
        items,
        runtime: { sandboxMode: defaultMode, telemetrySharing: sharing, workspaceRoot },
        generatedAt: Date.now(),
      }
    }

    // ---------------- Client RPC ----------------
    harness.handle('compliance.report', () => complianceReport())
    harness.handle('compliance.audit', () => ({ entries: audit.slice(-200).reverse() }))
    harness.handle('compliance.redact', (args) => redact(args && typeof args.text === 'string' ? args.text : ''))
    harness.handle('compliance.stats', () => ({
      auditCount: audit.length,
      redactionRules: RULES.length,
      reportScore: complianceReport().score,
    }))

    // ---------------- 模型可见合规工具 ----------------
    harness.registerTool(ctx, harness.defineTool({
      name: 'compliance_report',
      description: '运行企业合规自检（SOC2/GDPR），返回各项检查状态、总体评分与运行时事实。',
      parameters: {},
      output: { schema: { type: 'string' }, render(_a, v) { return [{ type: 'text', text: v }] } },
      execute() {
        const r = complianceReport()
        const lines = r.items.map((i) => '[' + i.status.toUpperCase() + '] ' + i.control + ' — ' + i.detail)
        return '合规评分: ' + r.score + '/100 (通过 ' + r.passed + '/' + r.total + ')\n' + lines.join('\n') + '\n运行时: 沙箱=' + r.runtime.sandboxMode + ', 遥测共享=' + r.runtime.telemetrySharing
      },
    }))

    harness.registerTool(ctx, harness.defineTool({
      name: 'compliance_redact',
      description: '对给定文本做敏感信息脱敏（邮箱、手机号、身份证、银行卡、API Key、JWT、私钥等），返回脱敏结果与命中统计。',
      parameters: { text: { type: 'string', required: true, description: '需要脱敏的原始文本' } },
      output: { schema: { type: 'string' }, render(_a, v) { return [{ type: 'text', text: v }] } },
      execute(args) {
        const r = redact(String(args && args.text !== undefined ? args.text : ''))
        const summary = r.findings.length ? r.findings.map((f) => f.type + 'x' + f.count).join(', ') : '无敏感信息'
        return '命中: ' + summary + '\n\n' + r.text
      },
    }))

    harness.registerTool(ctx, harness.defineTool({
      name: 'compliance_audit',
      description: '查询最近的操作审计日志（工具调用时间、名称、是否成功、脱敏后的参数、会话）。',
      parameters: { limit: { type: 'number', description: '返回最近 N 条（默认 20）' } },
      output: { schema: { type: 'string' }, render(_a, v) { return [{ type: 'text', text: v }] } },
      execute(args) {
        const limit = Math.min(Math.max(Number(args && args.limit) || 20, 1), 100)
        const rows = audit.slice(-limit).reverse().map((e) => {
          const t = new Date(e.time).toISOString()
          return t + ' | ' + e.tool + ' | ' + (e.ok ? 'OK' : 'FAIL') + (e.error ? ' (' + e.error + ')' : '') + (e.sessionId ? ' | session=' + e.sessionId : '')
        })
        return rows.length ? rows.join('\n') : '（暂无审计记录）'
      },
    }))
  },
}
