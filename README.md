# dsh-enterprise-compliance

企业级一体化合规插件（DeepSeek Harness / DSH）。三大能力支柱：

1. **SOC2 / GDPR 自动化合规自检** — `compliance_report` 模型工具：读取真实运行时事实，按
   CC6.1 / CC6.2 / CC7.2 / CC6.6 / A1.2 与 GDPR Art.5 / Art.25 逐项 PASS / WARN / FAIL 并打分。
2. **敏感信息拦截与脱敏** — `compliance_redact` 模型工具 + 9 类正则规则（邮箱、手机号、身份证、
   银行卡、API Key、JWT、Bearer、私钥、IP）；已挂载到 `session-telemetry/record` 瀑布流，
   遥测导出前自动脱敏（GDPR 数据最小化）。
3. **操作日志审计追溯** — `compliance_audit` 模型工具：监听 `tools/result`，记录每次工具调用的
   时间、工具名、成功 / 失败、会话 ID、**脱敏后的参数**（500 条内存环形缓冲）。

另附浏览器「企业合规中心」独立页面（设置 → 左侧导航，`settings.section`），订阅 Host 发布的合规状态，展示评分、检查项与最近审计。

## 目录结构

```
enterprise-compliance/
├── package.json        # npm 清单：dsh.bundle.patch / dsh.client / exports / peers
├── cordis.patch.yml    # bundle 补丁：把本插件插入 profile 的组合层
├── src/
│   ├── redact.js       # 脱敏引擎（纯函数、零依赖、可独立测试）
│   ├── index.js        # Host 插件（真实 Host API：tools.register / ctx.on / settings）
│   └── client.js       # Client 插件（__ModuleLoader__.load 包装，settings 侧边栏页）
├── lib/                # 提交的 Host 构建产物（git 安装无需 prepare）
├── client/client.js    # 提交的 Client 构建产物
├── scripts/build.mjs   # 同步 src → lib/client
├── test/               # node --test 单元测试
├── snapshot/           # 早期动态插件版本（compl-1/pkg-1）的源码快照，仅存档
├── README.md / LICENSE / .gitignore
```

## 安装

**本地 / git 安装**（`dsh plugin` 或插件市场，profile 根目录下有 `package.json` 与 `pnpm-workspace.yaml`）：

```bash
dsh plugin --profile desktop add github:<owner>/<repository>
# 或本地路径：
dsh plugin --profile desktop add file:./enterprise-compliance
```

安装后本包被加入 profile 的 `dsh.profile.bundles`，`cordis.patch.yml` 在下次启动自动应用。

本插件**只依赖 DSH 官方契约**（无 Desktop 专属服务），web 与 desktop profile 均可安装：

```bash
dsh plugin --profile web add file:./enterprise-compliance      # web 版
dsh plugin --profile desktop add file:./enterprise-compliance  # desktop 版
```

> **已知坑（compact-after-task）**：`dsh plugin add` 的 pnpm reconcile 会把 profile 里原本按
> 「patch insert」挂载的第三方插件一并挪进 `dsh.profile.bundles`，从而改变其 client 模块 id 的
> 期望（= 包名）。第三方 client 若未按包名注册 `__ModuleLoader__.load({ id })` 就会启动报错
> `loaded without registering "…"`。恢复方法：把该插件放回 profile 的 `cordis.patch.yml`
> insert，并从 `dsh.profile.bundles` 移除（本插件自身已按包名注册，无此问题）。

**npm 安装**：发布到 npm 后同样通过 `dsh plugin add dsh-enterprise-compliance` 安装。

## 发布到 GitHub / npm

```bash
# 1. 填入仓库地址后提交并推送
git init
git add .
git commit -m "feat: enterprise compliance plugin"
git remote add origin git@github.com:<owner>/<repository>.git
git push -u origin main
gh repo edit <owner>/<repository> --add-topic dsh-plugin

# 2. 发布到 npm
npm publish

# 3. （可选）提交到社区目录：见 submit-dsh-plugin 流程
#    https://github.com/imsai-sh/awesome-deepseek-harness-plugins
```

> 发布前把 `package.json` 的 `repository.url` 从占位符 `<owner>/<repository>` 改成真实地址；
> 如使用 npm scope，把 `name` 改为 `@<scope>/dsh-enterprise-compliance` 并同步 `cordis.patch.yml` 里的 `name`。

## 测试

三个测试套件，共 29 项，全部不依赖浏览器 / 真实 DSH 进程即可运行：

```bash
node test/redact.test.mjs       # 12 项：9 类脱敏规则 + redactDeep 递归/深度
node test/host.smoke.test.mjs   # 13 项：真实加载 lib/index.js，mock ctx 驱动 apply()
node test/client.smoke.test.mjs # 4 项：真实加载 client/client.js，校验工厂与渲染
npm test                        # 或 node --test test/（等价，node --test 会按文件分进程）
npm run build                   # 把 src/ 同步到 lib/ 与 client/
npm run check                   # build + test
```

**Host 冒烟测试覆盖**（直接执行插件代码，非仅语法检查）：
- 模块契约 `{ name, inject, apply }` 与 3 个工具注册（`ctx.tools.register(defineTool(...))`）；
- `compliance_report` 两种评分场景：全部服务挂载 → 100/100，危险沙箱 + 无审批 → 71/100（warn/fail 降级）；
- `compliance_redact` 掩码与命中统计；`compliance_audit` 初始空 / 入账后含工具名、OK/FAIL、session；
- `tools/result` 成功与失败事件入账、`session-telemetry/record` 脱敏接线（数据最小化）；
- `settings` 桥：命名空间注册、初始状态发布、5s 刷新定时器、节流与「无变化不重复写盘」；
- 缺全部服务时的健壮性（apply 不抛错、工具仍可用）。

**Client 冒烟测试覆盖**：`__ModuleLoader__.load({ id, factory })` 契约（**id = 包名**）、工厂返回
`{ name, inject: ['slots','locale','settingsScope'], apply }`、apply 接线（locale 注册 /
settingsScope 绑定 / `settings.section` 侧边栏页注册）、页面用真实 `React.createElement`
渲染出评分、检查项、审计行。

**Host 测试的 Guard 语义**：mock ctx 带 Cordis Guard（未在 `inject` 声明的 ctx 属性访问即抛错），
从模块导出的 `inject` 自动同步——若 apply 用了未声明的服务，测试当场红。历史上两处真实环境
Guard 翻车（`inject=[]` 却访问 `ctx.tools`、settings 未挂载即注册）都由这种盲区漏掉，现已堵上。

> **依赖说明**：仓库内 `node_modules/` 已 gitignore。沙箱本地测试时复制了 DSH 自带
> `@deepseek-ai/*`、`react` 等包以便运行上述冒烟测试；真实环境安装后由 DSH / npm 解析，
> 无需提交这些依赖。

> **schemastery API 注意**：本机 DSH 内置的 `@deepseek-ai/schemastery@3.18.1` **没有
> `.optional()`**（与 zod 不同），可选字段用 `.default(...)` 表达（`dsh-compact-after-task`
> 等内置插件同款写法）。`StatusSchema` 已按此适配。

## 架构说明

- **Host（src/index.js）**：ESM 导出 `{ name, apply(ctx) }`，用真实 Host 服务注册三个模型工具
  （`ctx.tools.register(defineTool(...))`），监听 `tools/result` 采集审计、`session-telemetry/record`
  做导出脱敏，`ctx.settings.register` 维护合规状态命名空间供 Client 读取。
- **Client（src/client.js）**：`settings.section` 侧边栏注册「企业合规中心」独立页面，订阅
  `enterprise-compliance` settings 命名空间；含 zh/en 双语词典。Host 端 `inject: ['tools','settings']`
  （settings 为硬依赖，保证命名空间注册时服务已挂载），Client 端 `inject: ['slots','locale','settingsScope']`。
- **副作用均 Fiber 所有**：`ctx.on` / `ctx.tools.register` / `ctx.settings.register` /
  `ctx.effect` / `slots.inject` / `locale.register`，插件卸载时自动清理。

## 已知限制

- 审计为内存环形缓冲（非持久化），仅采集插件运行期间的工具调用。
- 部分检查项结果取决于运行时服务是否挂载（审批 / 凭证 / 持久化 / 遥测）。
- 合规中心页面依赖 `settings` 服务存在；缺失时仅影响页面展示，不影响模型工具。

## 与早期动态插件版本的关系

`snapshot/` 保存了最初作为动态 Cordis 插件（`compl-1/pkg-1`，动态 `harness.*` API）运行的源码，
仅供存档对照。本工程已把逻辑改写为**可安装插件的真实 Host / Client API**。
