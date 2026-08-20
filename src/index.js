// enterprise-compliance — Host 端可安装插件
// 企业级一体化合规：SOC2/GDPR 合规自检、敏感信息脱敏、操作审计追溯与导出、
// 审计持久化、评分历史趋势、敏感数据扫描、GDPR 数据主体权利工具、
// 阈值报警与可配置策略。
//
// 使用真实 Host API：ctx.tools.register(defineTool(...))、ctx.on(...)、
// ctx.get(...)、ctx.settings.register(...)。纯 JS ESM，无需编译即可加载。
// 持久化走 settings 命名空间（由 dsh-settings 落盘到 settings.yaml），
// 与 dsh-compact-after-task 同款机制；文件扫描使用 node:fs（主进程原生 ESM）。
import { defineTool } from "@deepseek-ai/dsh-tools";
import z from "@deepseek-ai/schemastery";
import { RULES, redact, redactDeep } from "./redact.js";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, resolve, relative, isAbsolute, basename, sep } from "node:path";

export const name = "enterprise-compliance";

export const inject = ["tools", "settings"];

const STATUS_NS = "enterprise-compliance";
const AUDIT_CAP = 500;             // 内存审计环上限（含脱敏 args）
const AUDIT_PERSIST_DEFAULT = 100; // 持久化审计条数（不含 args，落盘 settings.yaml）
const HISTORY_CAP = 200;           // 评分历史上限
const DEFAULT_ALERT_THRESHOLD = 100;
const SCAN_MAX_FILE = 1024 * 1024; // 扫描单文件上限 1MB

// ---------------- 可配置策略（P3） ----------------
// 用户在 设置 里可改：报警阈值、持久化条数、检查项开关、脱敏规则开关。
const PolicySchema = z.object({
  alertThreshold: z.number().default(DEFAULT_ALERT_THRESHOLD),
  auditPersist: z.number().default(AUDIT_PERSIST_DEFAULT),
  checks: z.object({
    sandbox: z.boolean().default(true),
    approval: z.boolean().default(true),
    audit: z.boolean().default(true),
    redaction: z.boolean().default(true),
    credentials: z.boolean().default(true),
    persistence: z.boolean().default(true),
    telemetry: z.boolean().default(true),
  }).default({}),
  rules: z.object(Object.fromEntries(RULES.map((r) => [r.id, z.boolean().default(true)]))).default({}),
}).default({});

const defaultPolicy = () => PolicySchema({});

// Host 维护的合规状态命名空间（Client 设置卡片通过 settingsScope 订阅读取）。
const StatusSchema = z.object({
  score: z.number().default(0),
  passed: z.number().default(0),
  total: z.number().default(7),
  auditCount: z.number().default(0),
  items: z.array(z.object({
    id: z.string(),
    status: z.string(),
    control: z.string(),
    detail: z.string(),
  })).default([]),
  recent: z.array(z.object({
    time: z.number(),
    tool: z.string(),
    ok: z.boolean(),
    sessionId: z.string().default(""),
  })).default([]),
  // 持久化审计（不含 args），重启后回载进内存环。
  audit: z.array(z.object({
    time: z.number(),
    tool: z.string(),
    ok: z.boolean(),
    error: z.string().default(""),
    sessionId: z.string().default(""),
  })).default([]),
  // 评分历史趋势。
  history: z.array(z.object({
    time: z.number(),
    score: z.number(),
    passed: z.number(),
    total: z.number(),
  })).default([]),
  policy: PolicySchema,
  lastAlert: z.object({
    time: z.number().default(0),
    score: z.number().default(0),
    detail: z.string().default(""),
  }).default({}),
});

export function apply(ctx) {
  // ---------------- 操作审计（内存环形缓冲，含脱敏 args） ----------------
  const audit = []

  function pushAudit(entry) {
    audit.push(entry)
    if (audit.length > AUDIT_CAP) audit.splice(0, audit.length - AUDIT_CAP)
  }

  // ---------------- 评分历史 ----------------
  let history = []

  function recordHistory(r) {
    const last = history[history.length - 1]
    const now = Date.now()
    // 同分且 60s 内不重复记录，避免连续调用刷屏
    if (last && now - last.time < 60000 && last.score === r.score) return
    history.push({ time: now, score: r.score, passed: r.passed, total: r.total })
    if (history.length > HISTORY_CAP) history.splice(0, history.length - HISTORY_CAP)
  }

  // ---------------- 设置桥（status + policy 持久化到 settings.yaml） ----------------
  const settings = ctx.get("settings")
  let statusScope = undefined
  if (settings !== undefined && typeof settings.register === "function") {
    try {
      statusScope = settings.register(STATUS_NS, StatusSchema, {})
    } catch (e) {
      console.error("[enterprise-compliance] settings.register failed:", e)
      statusScope = undefined
    }
  }

  let policy = defaultPolicy()

  function readPolicy() {
    if (statusScope === undefined) return defaultPolicy()
    try {
      const v = statusScope.get()
      const p = v && typeof v === "object" && v.policy ? v.policy : {}
      return PolicySchema(p)
    } catch (e) {
      return policy
    }
  }

  // 启动时回载持久化数据（审计/历史/策略），实现"重启不丢证据"。
  function rehydrate() {
    if (statusScope === undefined) return
    try {
      const v = statusScope.get()
      if (!v || typeof v !== "object") return
      if (Array.isArray(v.audit)) {
        for (const e of v.audit.slice(-AUDIT_CAP)) {
          audit.push({ time: e.time, tool: e.tool, ok: !!e.ok, error: e.error || null, sessionId: e.sessionId || null, args: null })
        }
      }
      if (Array.isArray(v.history)) history = v.history.slice(-HISTORY_CAP)
      policy = PolicySchema(v.policy || {})
    } catch (e) { /* 回退默认 */ }
  }
  rehydrate()

  // ---------------- SOC2/GDPR 合规自检 ----------------
  function complianceReport() {
    const checks = policy.checks
    const sandbox = ctx.get("sandboxPolicy")
    const approval = ctx.get("approval")
    const persistence = ctx.get("sessionPersistence")
    const creds = ctx.get("credentials")
    const telemetry = ctx.get("sessionTelemetry")
    const defaultMode = sandbox ? String(sandbox.defaultMode) : "unknown"
    const sharing = telemetry ? String(telemetry.sharing) : "not-configured"
    const workspaceRoot = sandbox && typeof sandbox.workspaceRoot === "string" ? sandbox.workspaceRoot : null
    const sandboxSafe = defaultMode !== "danger-full-access"
    const items = []
    if (checks.sandbox) items.push({ id: "sandbox", standard: "SOC2", control: "CC6.1 文件沙箱隔离", status: sandboxSafe ? "pass" : "warn", detail: "默认沙箱模式: " + defaultMode })
    if (checks.approval) items.push({ id: "approval", standard: "SOC2", control: "CC6.2 权限审批", status: approval ? "pass" : "fail", detail: approval ? "审批服务已挂载" : "未检测到审批服务" })
    if (checks.audit) items.push({ id: "audit", standard: "SOC2", control: "CC7.2 操作审计", status: "pass", detail: "审计采集已启用，当前 " + audit.length + " 条" })
    if (checks.redaction) items.push({ id: "redaction", standard: "SOC2/GDPR", control: "CC7.3 / Art.25 敏感数据脱敏", status: "pass", detail: "脱敏引擎已启用（" + RULES.length + " 类规则）" })
    if (checks.credentials) items.push({ id: "credentials", standard: "SOC2", control: "CC6.6 凭证管理", status: creds ? "pass" : "warn", detail: creds ? "凭证服务已挂载" : "未检测到凭证服务" })
    if (checks.persistence) items.push({ id: "persistence", standard: "SOC2", control: "A1.2 持久化日志", status: persistence ? "pass" : "warn", detail: persistence ? "会话持久化已挂载" : "未检测到持久化" })
    if (checks.telemetry) items.push({ id: "telemetry", standard: "GDPR", control: "Art.5 导出数据最小化", status: "pass", detail: "遥测导出已脱敏，共享策略: " + sharing })
    if (items.length === 0) items.push({ id: "policy", standard: "SOC2", control: "策略配置", status: "pass", detail: "所有检查项均已关闭" })
    const passed = items.filter((i) => i.status === "pass").length
    return {
      score: items.length ? Math.round((passed / items.length) * 100) : 0,
      passed,
      total: items.length,
      items,
      runtime: { sandboxMode: defaultMode, telemetrySharing: sharing, workspaceRoot },
      generatedAt: Date.now(),
    }
  }

  // ---------------- 阈值报警（P2c） ----------------
  let alertActive = false
  let lastAlertState = null

  // 仅在"从正常跌到阈值以下"时触发一次（含恢复后清零），避免每个 tick 重复告警。
  function checkAlert(r) {
    const th = policy.alertThreshold
    const below = r.score < th
    if (below && !alertActive) {
      alertActive = true
      const failItems = r.items.filter((i) => i.status === "fail").map((i) => i.control)
      lastAlertState = {
        time: Date.now(),
        score: r.score,
        detail: failItems.length ? failItems.join("; ") : "评分低于阈值 " + th,
      }
      try {
        if (typeof ctx.emit === "function") ctx.emit("enterprise-compliance/alert", { ...lastAlertState })
      } catch (e) { /* 事件发布失败不影响主流程 */ }
      return lastAlertState
    }
    if (!below && alertActive) {
      alertActive = false
      lastAlertState = null
    }
    return lastAlertState
  }

  function textReport(r, hist) {
    const lines = r.items.map((i) => "[" + i.status.toUpperCase() + "] " + i.control + " — " + i.detail)
    let out = "合规评分: " + r.score + "/100 (通过 " + r.passed + "/" + r.total + ")\n" +
      lines.join("\n") +
      "\n运行时: 沙箱=" + r.runtime.sandboxMode + ", 遥测共享=" + r.runtime.telemetrySharing
    if (hist && hist.length) {
      out += "\n评分历史: " + hist.slice(-20).map((h) => h.score + "(" + h.passed + "/" + h.total + ")@" + new Date(h.time).toISOString().slice(0, 16)).join(" -> ")
    }
    return out
  }

  function mdReport(r, hist) {
    const rows = r.items.map((i) => "| " + i.control + " | " + i.status.toUpperCase() + " | " + i.detail + " |").join("\n")
    let out = "# 企业合规报告\n\n**评分: " + r.score + "/100（通过 " + r.passed + "/" + r.total + "）**\n\n" +
      "| 检查项 | 状态 | 说明 |\n|---|---|---|\n" + rows + "\n\n" +
      "_运行时: 沙箱=" + r.runtime.sandboxMode + "，遥测共享=" + r.runtime.telemetrySharing + "_"
    if (hist && hist.length) {
      out += "\n\n## 评分历史\n\n" + hist.slice(-20).map((h) => "- " + new Date(h.time).toISOString() + " → " + h.score + "/100").join("\n")
    }
    return out
  }

  // ---------------- 状态发布（含持久化审计/历史/策略/报警） ----------------
  let lastPublish = 0
  let lastSent = null
  function publishStatus() {
    if (statusScope === undefined) return
    try {
      if (Date.now() - lastPublish < 2000) return
      lastPublish = Date.now()
      policy = readPolicy()
      const r = complianceReport()
      const alert = checkAlert(r)
      const persistN = Math.max(0, Math.min(policy.auditPersist, AUDIT_CAP))
      const patch = {
        score: r.score,
        passed: r.passed,
        total: r.total,
        auditCount: audit.length,
        items: r.items.map((i) => ({ id: i.id, status: i.status, control: i.control, detail: i.detail })),
        recent: audit.slice(-20).reverse().map((e) => ({ time: e.time, tool: e.tool, ok: e.ok, sessionId: e.sessionId || undefined })),
        audit: audit.slice(-persistN).map((e) => ({ time: e.time, tool: e.tool, ok: e.ok, error: e.error || undefined, sessionId: e.sessionId || undefined })),
        history: history.slice(-HISTORY_CAP),
        policy,
        lastAlert: alert || { time: 0, score: 0, detail: "" },
      }
      const key = JSON.stringify(patch)
      if (key === lastSent) return // 无变化则不重复写盘（settings.update 会无条件 persist）
      lastSent = key
      statusScope.update(patch).catch(() => {})
    } catch (e) { /* 状态发布不得影响审计流水线 */ }
  }

  // ---------------- 操作审计采集（工具结果脱敏入账） ----------------
  ctx.on("tools/result", (exec, result) => {
    try {
      const tool = exec && typeof exec.name === "string" ? exec.name : "unknown"
      const args = exec && exec.args !== undefined ? redactDeep(exec.args, 0, policy.rules) : null
      const ok = !!(result && result.ok !== false)
      const error = result && result.error ? String(result.error) : null
      let sessionId = null
      try {
        const agent = exec && exec.agent
        if (agent && agent.session && typeof agent.session.id === "string") sessionId = agent.session.id
      } catch (e) { /* ignore */ }
      pushAudit({ time: Date.now(), tool, ok, error, args, sessionId })
      publishStatus()
    } catch (e) { /* 审计不得打断工具流水线 */ }
  })

  // ---------------- 遥测导出脱敏（GDPR 数据最小化，遵守策略规则开关） ----------------
  ctx.on("session-telemetry/record", (record, next) => {
    const base = next()
    try {
      return base && typeof base === "object" ? redactDeep(base, 0, policy.rules) : base
    } catch (e) {
      return base
    }
  })

  // 周期性刷新状态（如策略/遥测变化），5s 一次，随 Fiber 自动清理。
  const timer = ctx.get("timer")
  if (timer !== undefined && typeof timer.interval === "function") {
    ctx.effect(() => timer.interval(() => publishStatus(), 5000), "enterprise-compliance: status refresh")
  }
  publishStatus()

  // ---------------- 模型可见合规工具 ----------------
  ctx.tools.register(defineTool({
    name: "compliance_report",
    description: "运行企业合规自检（SOC2/GDPR），返回各项检查状态、总体评分与运行时事实；可导出 JSON/Markdown 并附带评分历史趋势。",
    parameters: {
      format: { type: "string", description: "输出格式：summary | json | markdown（默认 summary）" },
      history: { type: "boolean", description: "是否附带评分历史趋势（默认 false）" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    execute(args) {
      policy = readPolicy()
      const r = complianceReport()
      recordHistory(r)
      publishStatus()
      const fmt = args && typeof args.format === "string" ? args.format : "summary"
      const withHistory = !!(args && args.history)
      if (fmt === "json") {
        return Promise.resolve(JSON.stringify({
          report: { score: r.score, passed: r.passed, total: r.total, items: r.items, runtime: r.runtime, generatedAt: r.generatedAt },
          history: withHistory ? history.slice(-20) : undefined,
        }, null, 2))
      }
      if (fmt === "markdown") return Promise.resolve(mdReport(r, withHistory ? history : undefined))
      return Promise.resolve(textReport(r, withHistory ? history : undefined))
    },
  }))

  ctx.tools.register(defineTool({
    name: "compliance_redact",
    description: "对给定文本做敏感信息脱敏（邮箱、手机号、身份证、银行卡、API Key、JWT、私钥等），返回脱敏结果与命中统计；可指定启用规则。",
    parameters: {
      text: { type: "string", required: true, description: "需要脱敏的原始文本" },
      rules: { type: "array", description: "仅启用指定规则 id（如 ['email','phone']），默认用策略配置" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    execute(args) {
      policy = readPolicy()
      const text = String(args && args.text !== undefined ? args.text : "")
      const enabled = Array.isArray(args && args.rules)
        ? Object.fromEntries(RULES.map((r) => [r.id, args.rules.includes(r.id)]))
        : policy.rules
      const r = redact(text, enabled)
      const summary = r.findings.length ? r.findings.map((f) => f.type + "x" + f.count).join(", ") : "无敏感信息"
      return Promise.resolve("命中: " + summary + "\n\n" + r.text)
    },
  }))

  ctx.tools.register(defineTool({
    name: "compliance_audit",
    description: "查询操作审计日志（工具调用时间、名称、是否成功、脱敏参数、会话），支持 text/json/csv 导出与按工具、会话、时间过滤。",
    parameters: {
      limit: { type: "number", description: "返回最近 N 条（默认 20，最大 500）" },
      format: { type: "string", description: "输出格式：text | json | csv（默认 text）" },
      since: { type: "number", description: "仅返回晚于该时间戳（epoch 毫秒）的记录" },
      tool: { type: "string", description: "按工具名精确过滤" },
      sessionId: { type: "string", description: "按会话 ID 精确过滤" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    execute(args) {
      let rows = audit.slice()
      if (args && Number.isFinite(args.since)) rows = rows.filter((e) => e.time >= args.since)
      if (args && typeof args.tool === "string" && args.tool) rows = rows.filter((e) => e.tool === args.tool)
      if (args && typeof args.sessionId === "string" && args.sessionId) rows = rows.filter((e) => e.sessionId === args.sessionId)
      const limit = Math.min(Math.max(Number(args && args.limit) || 20, 1), AUDIT_CAP)
      rows = rows.slice(-limit).reverse()
      const fmt = args && typeof args.format === "string" ? args.format : "text"
      if (fmt === "json") {
        return Promise.resolve(JSON.stringify(rows.map((e) => ({
          time: e.time, iso: new Date(e.time).toISOString(), tool: e.tool, ok: e.ok,
          error: e.error || undefined, sessionId: e.sessionId || undefined, args: e.args || undefined,
        })), null, 2))
      }
      if (fmt === "csv") {
        const head = "time,tool,ok,error,sessionId"
        const lines = rows.map((e) => [
          new Date(e.time).toISOString(),
          '"' + String(e.tool).replace(/"/g, '""') + '"',
          e.ok ? "OK" : "FAIL",
          '"' + String(e.error || "").replace(/"/g, '""') + '"',
          '"' + String(e.sessionId || "").replace(/"/g, '""') + '"',
        ].join(","))
        return Promise.resolve(lines.length ? head + "\n" + lines.join("\n") : head)
      }
      const lines2 = rows.map((e) => {
        const t = new Date(e.time).toISOString()
        return t + " | " + e.tool + " | " + (e.ok ? "OK" : "FAIL") + (e.error ? " (" + e.error + ")" : "") + (e.sessionId ? " | session=" + e.sessionId : "")
      })
      return Promise.resolve(lines2.length ? lines2.join("\n") : "（暂无审计记录）")
    },
  }))

  ctx.tools.register(defineTool({
    name: "compliance_scan",
    description: "扫描文件/目录中的敏感信息（邮箱、手机号、API Key、JWT、私钥等），返回每文件命中统计与脱敏样例。默认限制在工作区内。",
    parameters: {
      path: { type: "string", required: true, description: "要扫描的文件或目录路径（相对工作区或绝对路径）" },
      recursive: { type: "boolean", description: "目录递归扫描（默认 false）" },
      allowOutside: { type: "boolean", description: "允许扫描工作区之外路径（默认 false）" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    async execute(args) {
      policy = readPolicy()
      const target = String(args && args.path || "").trim()
      const recursive = !!(args && args.recursive)
      const allowOutside = !!(args && args.allowOutside)
      if (!target) return "路径不能为空"
      let workspaceRoot = null
      try {
        const s = ctx.get("sandboxPolicy")
        if (s && typeof s.workspaceRoot === "string") workspaceRoot = s.workspaceRoot
      } catch (e) { /* ignore */ }
      const abs = isAbsolute(target) ? target : (workspaceRoot ? resolve(workspaceRoot, target) : resolve(target))
      if (!allowOutside && workspaceRoot) {
        const root = resolve(workspaceRoot)
        const r = relative(root, abs)
        if (r === ".." || r.startsWith(".." + sep) || isAbsolute(r)) {
          return "路径在工作区之外（如确需扫描可传 allowOutside=true）：" + abs
        }
      }
      const results = []
      const errors = []
      const disp = (p) => relative(abs, p) || basename(p) // 单文件时显示文件名
      const pending = [{ p: abs }]
      while (pending.length) {
        const { p } = pending.pop()
        let st
        try { st = await stat(p) } catch (e) { errors.push(disp(p) + ": " + e.message); continue }
        if (st.isDirectory()) {
          if (!recursive) continue
          let entries
          try { entries = await readdir(p) } catch (e) { errors.push(disp(p) + ": " + e.message); continue }
          for (const name of entries) pending.push({ p: join(p, name) })
          continue
        }
        if (!st.isFile()) continue
        if (st.size > SCAN_MAX_FILE) { errors.push(disp(p) + ": 超过 1MB 跳过"); continue }
        let buf
        try { buf = await readFile(p) } catch (e) { errors.push(disp(p) + ": " + e.message); continue }
        if (buf.includes(0)) continue // 跳过二进制
        const r2 = redact(buf.toString("utf8"), policy.rules)
        if (r2.findings.length) {
          results.push({
            path: disp(p),
            size: st.size,
            findings: r2.findings,
            sample: r2.text.slice(0, 400),
          })
        }
      }
      const totalHits = results.reduce((n, f) => n + f.findings.reduce((m, x) => m + x.count, 0), 0)
      let out = "扫描路径: " + abs + "\n命中文件: " + results.length + "，敏感命中: " + totalHits + " 处" +
        (errors.length ? "\n跳过/失败: " + errors.length + " 项" : "")
      for (const f of results) {
        out += "\n\n[" + f.path + "] (" + f.size + "B) 命中: " + f.findings.map((x) => x.type + "x" + x.count).join(", ")
        out += "\n样例: " + f.sample
      }
      if (!results.length && !errors.length) out += "\n（未发现敏感信息）"
      return out
    },
  }))

  ctx.tools.register(defineTool({
    name: "compliance_data_export",
    description: "导出本插件采集的用户相关数据（GDPR Art.20 数据可携带权）：操作审计、评分历史、当前状态与策略，JSON 格式。",
    parameters: {
      format: { type: "string", description: "输出格式：json（默认）" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    execute() {
      let status = null
      try { status = statusScope ? statusScope.get() : null } catch (e) { /* ignore */ }
      return Promise.resolve(JSON.stringify({
        exportedAt: new Date().toISOString(),
        provider: "@xiaobanli/dsh-enterprise-compliance",
        data: {
          status,
          audit: audit.map((e) => ({ time: e.time, tool: e.tool, ok: e.ok, error: e.error || undefined, sessionId: e.sessionId || undefined })),
          history: history.slice(-HISTORY_CAP),
          policy,
        },
      }, null, 2))
    },
  }))

  ctx.tools.register(defineTool({
    name: "compliance_data_erase",
    description: "擦除本插件采集的数据（GDPR Art.17 删除权）：操作审计、评分历史、报警状态。仅影响本插件自身采集的数据，需 confirm: true。",
    parameters: {
      confirm: { type: "boolean", required: true, description: "必须为 true 才会真正擦除" },
    },
    output: { schema: { type: "json" }, render: (_args, value) => [{ type: "text", text: String(value) }] },
    execute(args) {
      if (!(args && args.confirm === true)) return Promise.resolve("未确认（需 confirm: true），未擦除任何数据")
      audit.length = 0
      history = []
      lastAlertState = null
      alertActive = false
      lastSent = null
      if (statusScope !== undefined) {
        try {
          statusScope.update({ audit: [], history: [], recent: [], lastAlert: { time: 0, score: 0, detail: "" } }).catch(() => {})
        } catch (e) { /* ignore */ }
      }
      return Promise.resolve("已擦除本插件采集的数据（审计/历史/报警状态）")
    },
  }))
}
