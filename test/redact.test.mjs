// enterprise-compliance — 脱敏引擎单元测试（纯函数，无需 DSH 即可运行）
// 运行：node --test test/
import test from "node:test";
import assert from "node:assert/strict";
import { RULES, redact, redactDeep } from "../src/redact.js";

test("覆盖 9 类敏感信息规则", () => {
  assert.equal(RULES.length, 9);
  const ids = RULES.map((r) => r.id);
  for (const id of ["email", "phone", "idcard", "bankcard", "apikey", "jwt", "bearer", "privatekey", "ip"]) {
    assert.ok(ids.includes(id), "缺少规则 " + id);
  }
});

test("脱敏邮箱", () => {
  const r = redact("请联系 a@b.com 或 team@example.org");
  assert.equal(r.text, "请联系 [email] 或 [email]");
  assert.ok(r.findings.some((f) => f.type === "email" && f.count === 2));
});

test("脱敏手机号", () => {
  const r = redact("13800138000");
  assert.equal(r.text, "[phone]");
});

test("脱敏身份证号", () => {
  const r = redact("110101199003070011");
  assert.equal(r.text, "[id-card]");
});

test("脱敏银行卡号（16-19 位纯数字）", () => {
  const r = redact("6222021234567890123");
  assert.equal(r.text, "[bank-card]");
});

test("脱敏 API Key / JWT / Bearer", () => {
  const input = "sk-abcdefghijklmnop1234567890 " +
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c " +
    "Bearer abcdefghijklmnopqrstuvwxyz1234567890ABC";
  const r = redact(input);
  assert.equal(r.text, "[api-key] [jwt] [bearer]");
});

test("脱敏多行 PEM 私钥", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
  const r = redact(pem);
  assert.equal(r.text, "[private-key]");
});

test("脱敏 IPv4", () => {
  const r = redact("server 10.0.0.1:8080");
  assert.equal(r.text, "server [ip]:8080");
});

test("普通文本不受影响且零命中", () => {
  const r = redact("hello world, 没有敏感信息");
  assert.equal(r.text, "hello world, 没有敏感信息");
  assert.equal(r.findings.length, 0);
});

test("非字符串输入返回安全包装", () => {
  assert.equal(redact(null).text, "null");
  assert.equal(redact(undefined).text, "undefined");
  assert.equal(redact(42).findings.length, 0);
});

test("redactDeep 递归脱敏对象与数组（不破坏结构）", () => {
  const deep = redactDeep({
    user: "a@b.com",
    nested: { phone: "13800138000" },
    list: ["sk-abcdefghijklmnop1234567890", 42, null],
  }, 0);
  assert.equal(deep.user, "[email]");
  assert.equal(deep.nested.phone, "[phone]");
  assert.equal(deep.list[0], "[api-key]");
  assert.equal(deep.list[1], 42);
  assert.equal(deep.list[2], null);
});

test("redactDeep 深度上限内仍能脱敏字符串", () => {
  const value = { a: { b: { c: "a@b.com" } } };
  const out = redactDeep(value, 0);
  assert.equal(out.a.b.c, "[email]");
});

test("规则开关：enabledRules 关闭某规则后该规则不再命中", () => {
  const input = "a@b.com 13800138000";
  const onlyPhone = redact(input, { email: false, phone: true });
  assert.equal(onlyPhone.text, "a@b.com [phone]", "只开 phone 时邮箱应保留");
  const onlyEmail = redact(input, { email: true, phone: false });
  assert.equal(onlyEmail.text, "[email] 13800138000", "只开 email 时手机号应保留");
  const allOff = redact(input, { email: false, phone: false });
  assert.equal(allOff.text, input, "全关时应原样返回");
  assert.equal(allOff.findings.length, 0);
});

test("redactDeep 透传规则开关", () => {
  const deep = redactDeep({ email: "a@b.com", phone: "13800138000" }, 0, { email: false });
  assert.equal(deep.email, "a@b.com", "关闭 email 后不应脱敏");
  assert.equal(deep.phone, "[phone]", "未关闭的 phone 应脱敏");
});
