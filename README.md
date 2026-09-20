# egress-guard

[pi agent](https://github.com/earendil-works/pi) 扩展：控制"什么内容进模型"的出站防护。在执行前拦截敏感文件读取，在执行后与出站前对密钥做脱敏。

## 功能

三层防护：

| 层 | 钩子 | 作用 |
|---|---|---|
| L1 | `tool_call` | 执行前拦截 `read` / `ls` 与 `bash` / `powershell` 触达敏感路径；禁写 pi 凭证与 git 元数据 |
| L2 | `tool_result` | 执行后对工具结果文本脱敏（落盘会话文件同样被保护） |
| L3 | `before_provider_request` | 出站前深度遍历整个 payload 脱敏（兜住手贴密钥、上下文文件） |

**L1 拦截范围**

- 文件名精确匹配：`.env`、`id_rsa`、`id_dsa`、`id_ecdsa`、`id_ed25519`、`credentials`、`creds.json`、`auth.json`、`trust.json`、`.npmrc`、`.pypirc`、`.netrc`、`.git-credentials`、`.gnupg`
- 文件名通配：`.env.{local,dev,development,test,prod,production,staging,secret}[s]`、`id_*`、`*.pem` / `*.key` / `*.p12` / `*.pfx`、`auth.json*`、`web-push.json`
- 路径片段：`/.ssh/`、`/.aws/`、`/.gnupg/`、`/.docker/config.json`、`secrets/`、`.kube/config`

**L2 / L3 脱敏规则**

带前缀 token（`sk-*`、`ghp_*`、`github_pat_*`、`glpat-*`、`xox[baprs]-*`、`AKIA*`、`AIza*`、`hf_*`、`sk-or-*`）、智谱 GLM key（`{32位hex}.{16位字母数字}`）、JWT、私钥块，以及 `*_KEY` / `*_SECRET` / `*_TOKEN` / `*_PASSWORD` 形式的 KV 赋值（自动跳过 `process.env.X`、`${VAR}`、`<placeholder>` 等引用型值）。

## 安装

将 `z-egress-guard.ts` 放入 `~/.pi/agent/extensions/`（全局），或 `<项目>/.pi/extensions/`（需项目信任），然后 `/reload` 热重载。

> **请保留文件名前缀 `z-`**：`secret-scan` 与本扩展共用 `before_provider_request` 钩子，pi 按文件名字母序依次调用。`z-` 保证 `secret-scan` 先看到**原始** payload 去告警，本扩展后做脱敏 —— 观测与防护双全。若改名到 `s` 之前，`secret-scan` 只会看到已脱敏内容而不再告警。

## 配置

在文件顶部修改：

- `SCAN_PAYLOAD`（L3 总开关，默认 `true`）
- `BLOCKED_BASENAMES` / `BLOCKED_BASENAME_GLOBS` / `BLOCKED_FRAGMENTS`（L1 敏感清单）
- `PROTECTED_WRITE_FRAGMENTS`（写保护清单）
- `REDACT_RULES`（值形态脱敏规则）

## 边界（必读）

- **这不是安全边界**，只是一个减少误发的护栏。真隔离请用容器，见 pi 的 `docs/security.md`。
- L1 的 shell 拦截是启发式的 —— 模型可用任意语言内联脚本绕过路径匹配。
- 图片（截图含密钥）无法脱敏，只能靠 L1 拦截。
- L3 会把用户手贴的真实密钥也脱敏。若确实想让模型看到真实密钥，先关掉 `SCAN_PAYLOAD`。
- 被 L1 拦截的调用不会触发 `tool_execution_end`，因此本扩展自行对"同目标重复拦截"升级：第 3 次强化提示，第 5 次 `terminate`。

## 说明

- 扩展内不含任何密钥，所有规则均为本地匹配
- `z-` 前缀的命名约定同时服务于上面提到的钩子顺序要求
