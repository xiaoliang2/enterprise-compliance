// ============================================================================
// enterprise-compliance — Client 端源码（compl-1 / pkg-1 导出快照）
// ----------------------------------------------------------------------------
// 本文件内容是 cordis_define 的 code.client 参数原值：一个返回 Cordis Plugin
// 的纯 JavaScript 函数体（React 使用 React.createElement，无 JSX）。
// 重新注册时把本文件完整内容作为 code.client 传入即可。
// ============================================================================
return {
  apply(ctx) {
    styles.insert(`
      .ec-page { font-size: 13px; line-height: 1.6; }
      .ec-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
      .ec-score { font-size: 24px; font-weight: 700; color: var(--dsw-alias-label-primary); }
      .ec-badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
      .ec-pass { background: var(--dsw-alias-state-success-primary); color: #fff; }
      .ec-warn { background: var(--dsw-alias-state-warn-primary); color: #000; }
      .ec-fail { background: var(--dsw-alias-state-error-primary); color: #fff; }
      .ec-card { border: 1px solid var(--dsw-alias-border-l1); border-radius: 8px; padding: 10px; margin-bottom: 10px; background: var(--dsw-alias-bg-layer-1); }
      .ec-row { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--dsw-alias-border-l1); }
      .ec-muted { color: var(--dsw-alias-label-secondary); font-size: 12px; }
      .ec-btn { cursor: pointer; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 6px; padding: 4px 10px; font-size: 12px; }
      .ec-btn:hover { border-color: var(--dsw-alias-brand-primary); }
      .ec-ta { width: 100%; box-sizing: border-box; min-height: 64px; resize: vertical; background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px; padding: 6px 8px; font-size: 12px; }
      .ec-table { width: 100%; border-collapse: collapse; font-size: 12px; }
      .ec-table th, .ec-table td { text-align: left; padding: 4px 6px; border-bottom: 1px solid var(--dsw-alias-border-l1); }
      .ec-table th { color: var(--dsw-alias-label-secondary); font-weight: 500; }
      .ec-ok { color: var(--dsw-alias-state-success-primary); }
      .ec-err { color: var(--dsw-alias-state-error-primary); }
    `)

    function CompliancePage() {
      const [report, setReport] = React.useState(null)
      const [audit, setAudit] = React.useState([])
      const [text, setText] = React.useState('联系 test@example.com 或 13800138000，密钥 sk-1234567890abcdef1234567890')
      const [redacted, setRedacted] = React.useState(null)

      const refresh = React.useCallback(() => {
        host.call('compliance.report').then((r) => setReport(r)).catch(() => {})
        host.call('compliance.audit').then((a) => setAudit(a && a.entries ? a.entries : [])).catch(() => {})
      }, [])

      React.useEffect(() => { refresh() }, [refresh])

      const onRedact = () => {
        host.call('compliance.redact', { text }).then((r) => setRedacted(r)).catch(() => {})
      }

      const rows = []
      if (report) {
        for (const it of report.items) {
          rows.push(React.createElement('div', { key: it.id, className: 'ec-row' },
            React.createElement('span', { className: 'ec-badge ec-' + it.status }, it.status.toUpperCase()),
            React.createElement('span', { style: { fontWeight: 500 } }, it.control),
            React.createElement('span', { className: 'ec-muted', style: { marginLeft: 'auto' } }, it.detail)))
        }
      }

      const auditRows = audit.slice(0, 20).map((e, i) =>
        React.createElement('tr', { key: i },
          React.createElement('td', null, new Date(e.time).toLocaleTimeString()),
          React.createElement('td', null, e.tool),
          React.createElement('td', { className: e.ok ? 'ec-ok' : 'ec-err' }, e.ok ? 'OK' : 'FAIL'),
          React.createElement('td', { className: 'ec-muted' }, e.sessionId || '')))

      return React.createElement('div', { className: 'ec-page' },
        React.createElement('div', { className: 'ec-head' },
          React.createElement('span', { className: 'ec-score' }, report ? report.score + '/100' : '…'),
          React.createElement('span', { className: 'ec-muted' }, report ? 'SOC2/GDPR 通过 ' + report.passed + '/' + report.total : '加载中…'),
          React.createElement('button', { className: 'ec-btn', onClick: refresh }, '刷新')),
        React.createElement('div', { className: 'ec-card' },
          React.createElement('div', { style: { fontWeight: 600, marginBottom: 4 } }, '合规检查项'),
          rows.length ? rows : React.createElement('div', { className: 'ec-muted' }, '加载中…')),
        React.createElement('div', { className: 'ec-card' },
          React.createElement('div', { style: { fontWeight: 600, marginBottom: 4 } }, '敏感信息脱敏测试'),
          React.createElement('textarea', { className: 'ec-ta', value: text, onChange: (e) => setText(e.target.value) }),
          React.createElement('div', { style: { marginTop: 6, display: 'flex', gap: 8, alignItems: 'center' } },
            React.createElement('button', { className: 'ec-btn', onClick: onRedact }, '脱敏'),
            redacted && redacted.findings && redacted.findings.length
              ? React.createElement('span', { className: 'ec-muted' }, '命中: ' + redacted.findings.map((f) => f.type + 'x' + f.count).join(', '))
              : null),
          redacted ? React.createElement('pre', { className: 'ec-muted', style: { marginTop: 6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' } }, redacted.text) : null),
        React.createElement('div', { className: 'ec-card' },
          React.createElement('div', { style: { fontWeight: 600, marginBottom: 4 } }, '操作审计日志（最近 ' + audit.length + ' 条，参数已脱敏）'),
          React.createElement('table', { className: 'ec-table' },
            React.createElement('thead', null, React.createElement('tr', null,
              React.createElement('th', null, '时间'), React.createElement('th', null, '工具'),
              React.createElement('th', null, '结果'), React.createElement('th', null, '会话'))),
            React.createElement('tbody', null, auditRows)))
      )
    }

    const slots = ctx.get('slots')
    if (slots === undefined) return
    slots.inject('settings.section', () => slots.register(
      { name: 'settings.section', id: 'enterprise-compliance', order: 30, label: '合规中心' },
      () => React.createElement(CompliancePage, null),
    ))
  },
}
