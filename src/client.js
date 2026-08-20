// enterprise-compliance — client bundle (browser)
// 在 设置 左侧导航注册一个「企业合规中心」独立页面（settings.section）：
//   - 合规评分（score/100）与通过项数；
//   - SOC2/GDPR 检查项清单（PASS/WARN/FAIL）；
//   - 最近操作审计（时间/工具/结果/会话，参数已在 Host 端脱敏）。
// 数据来源：订阅 Host 维护的 settings namespace `enterprise-compliance`。
// 构建格式与 DSH 其他 client 插件一致：window.__ModuleLoader__.load(...)。

window.__ModuleLoader__.load({
  id: "@xiaobanli/dsh-enterprise-compliance",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    var React = require("react");
    var useSyncExternalStore = React.useSyncExternalStore;

    var NS = "enterprise-compliance";

    var zh = {
      "card.title": "企业合规中心",
      "card.score": "合规评分",
      "card.passed": "通过",
      "card.total": "项",
      "card.items": "SOC2/GDPR 检查项",
      "card.recent": "最近操作审计（参数已脱敏）",
      "card.tools": "模型工具：compliance_report / compliance_redact / compliance_audit",
      "card.empty": "等待 Host 发布状态…",
      "card.pass": "PASS",
      "card.warn": "WARN",
      "card.fail": "FAIL",
      "card.noAudit": "（暂无审计记录）",
      "card.alert": "⚠ 合规告警",
      "card.history": "评分趋势"
    };
    var en = {
      "card.title": "Enterprise Compliance Center",
      "card.score": "Compliance score",
      "card.passed": "passed",
      "card.total": "items",
      "card.items": "SOC2/GDPR checklist",
      "card.recent": "Recent audit (args redacted)",
      "card.tools": "Model tools: compliance_report / compliance_redact / compliance_audit",
      "card.empty": "Waiting for Host status…",
      "card.pass": "PASS",
      "card.warn": "WARN",
      "card.fail": "FAIL",
      "card.noAudit": "(no audit records)",
      "card.alert": "⚠ Compliance alert",
      "card.history": "Score trend"
    };

    var styles = {
      card: { display: "flex", flexDirection: "column", gap: "8px", padding: "4px 0" },
      head: { display: "flex", alignItems: "baseline", gap: "10px" },
      score: { fontSize: "22px", fontWeight: 700, color: "var(--dsw-alias-label-primary)" },
      sectionTitle: { fontSize: "13px", fontWeight: 600, color: "var(--dsw-alias-label-primary)", marginTop: "6px" },
      row: { display: "flex", alignItems: "center", gap: "8px", fontSize: "12px" },
      label: { fontSize: "13px", color: "var(--dsw-alias-label-primary)" },
      muted: { fontSize: "12px", color: "var(--dsw-alias-label-secondary)", marginLeft: "auto" },
      hint: { fontSize: "12px", lineHeight: "18px", color: "var(--dsw-alias-label-secondary)", margin: "0" },
      badge: { display: "inline-block", padding: "0 6px", borderRadius: "999px", fontSize: "11px", fontWeight: 600 },
      pass: { background: "var(--dsw-alias-state-success-primary)", color: "#fff" },
      warn: { background: "var(--dsw-alias-state-warn-primary)", color: "#000" },
      fail: { background: "var(--dsw-alias-state-error-primary)", color: "#fff" },
      ok: { color: "var(--dsw-alias-state-success-primary)", fontWeight: 600 },
      err: { color: "var(--dsw-alias-state-error-primary)", fontWeight: 600 },
      alert: { background: "var(--dsw-alias-state-warn-primary)", color: "#000", padding: "4px 8px", borderRadius: "4px", fontSize: "12px" }
    };

    function badge(status) {
      return { ...styles.badge, ...styles[status] };
    }

    /**
     * 合规状态卡片：订阅 settings namespace `enterprise-compliance`。
     * @param {object} props - 来自注册 inject:{ t, scope }。
     */
    function ComplianceCard({ t, scope }) {
      var snapshot = useSyncExternalStore(function (subscribe) {
        return scope.subscribe(subscribe);
      }, function () {
        return scope.getSnapshot();
      });
      var value = snapshot.value ?? {};
      var score = typeof value.score === "number" ? value.score : null;
      var passed = typeof value.passed === "number" ? value.passed : 0;
      var total = typeof value.total === "number" ? value.total : 0;
      var auditCount = typeof value.auditCount === "number" ? value.auditCount : 0;
      var items = Array.isArray(value.items) ? value.items : [];
      var recent = Array.isArray(value.recent) ? value.recent : [];
      var lastAlert = value.lastAlert && typeof value.lastAlert === "object" ? value.lastAlert : null;
      var history = Array.isArray(value.history) ? value.history : [];

      return React.createElement("div", { style: styles.card },
        React.createElement("div", { style: styles.head },
          React.createElement("span", { style: styles.score }, score !== null ? score + "/100" : "…"),
          React.createElement("span", { style: styles.hint }, t("card.passed") + " " + passed + "/" + total)),
        lastAlert && lastAlert.detail
          ? React.createElement("div", { style: styles.alert }, t("card.alert") + "：" + lastAlert.detail + "（" + lastAlert.score + "/100）")
          : null,
        React.createElement("p", { style: styles.hint }, t("card.tools")),
        React.createElement("div", { style: styles.sectionTitle }, t("card.items")),
        items.length === 0
          ? React.createElement("p", { style: styles.hint }, t("card.empty"))
          : items.map(function (it) {
              return React.createElement("div", { key: it.id, style: styles.row },
                React.createElement("span", { style: badge(it.status) }, t("card." + it.status)),
                React.createElement("span", { style: styles.label }, it.control));
            }),
        history.length > 0 ? React.createElement("div", null,
          React.createElement("div", { style: styles.sectionTitle }, t("card.history")),
          React.createElement("div", { style: styles.row },
            history.slice(-10).map(function (h, i) {
              return React.createElement("span", { key: i, style: h.score >= 100 ? styles.ok : styles.err }, h.score + " ");
            }))
        ) : null,
        React.createElement("div", { style: styles.sectionTitle }, t("card.recent") + "（" + auditCount + "）"),
        recent.length === 0
          ? React.createElement("p", { style: styles.hint }, t("card.noAudit"))
          : recent.slice(0, 10).map(function (e, i) {
              return React.createElement("div", { key: i, style: styles.row },
                React.createElement("span", { style: e.ok ? styles.ok : styles.err }, e.ok ? "OK" : "FAIL"),
                React.createElement("span", { style: styles.label }, e.tool),
                React.createElement("span", { style: styles.muted }, e.sessionId || ""));
            })
      );
    }

    var name = "enterprise-compliance";
    var inject = ["slots", "locale", "settingsScope"];

    function apply(ctx) {
      ctx.effect(function () {
        return ctx.locale.register(NS, { zh: zh, en: en });
      }, "enterprise-compliance: dictionaries");
      var t = ctx.locale.bind(NS);
      var scope = ctx.settingsScope.bind({ namespace: NS });
      ctx.slots.inject("settings.section", function () {
        return ctx.slots.register({
          name: "settings.section",
          id: "enterprise-compliance",
          order: 30,
          label: function () { return t("card.title"); }
        }, function () {
          return React.createElement(ComplianceCard, { t: t, scope: scope });
        });
      });
    }

    exports.name = name;
    exports.inject = inject;
    exports.apply = apply;
    return module.exports;
  }
});
