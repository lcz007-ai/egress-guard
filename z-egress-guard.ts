/**
 * egress-guard v2 —— 控制"什么内容进模型"的 pi 扩展
 *
 * 三层防护：
 *   L1 tool_call           执行前拦截 read/ls + bash/powershell 触达敏感路径
 *   L2 tool_result         执行后对结果文本脱敏（同时保护本地会话文件）
 *   L3 before_provider_request  出站前扫描整个 payload（兜住手贴密钥/上下文文件）
 *
 * 安装：~/.pi/agent/extensions/egress-guard.ts（全局）
 *       或 <项目>/.pi/extensions/egress-guard.ts（需项目信任），然后 /reload
 *
 * 边界（必读）：
 *   - L1 的 bash 拦截是启发式，模型可用任意语言内联脚本绕过路径匹配
 *   - 图片（截图含密钥）无法脱敏，只能靠 L1 拦截
 *   - L3 会把用户手贴的真实密钥也脱敏——想让模型看到真密钥时先关掉 SCAN_PAYLOAD
 *   - 这不是安全边界；真隔离用容器（见 docs/security.md）
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// ======================= 配置 =======================

/** L1：文件名精确匹配（对 basename，大小写不敏感） */
const BLOCKED_BASENAMES = new Set([
  ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
  "credentials", "creds.json", "auth.json", "trust.json",
  ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".gnupg",
]);

/** L1：basename 通配（对 basename）—— .env.* 只列真实环境层，放行 example/sample 模板 */
const BLOCKED_BASENAME_GLOBS: RegExp[] = [
  /^\.env\.(local|dev|development|test|prod|production|staging|secret)s?$/i,
  /^id_[a-z0-9_]+$/i,   // id_* 私钥家族
  /\.(pem|key|p12|pfx)$/i,
  /^auth\.json(\.|$)/i, // pi 凭证及其 .bak 备份
  /^web-push\.json$/i,  // web 推送凭证
];

/** L1：路径片段匹配（对正斜杠归一化后的全路径，大小写不敏感）
 *  注意：不含 .pi/agent/ —— 那会误拦 models.json/settings.json 的读取，
 *  妨碍模型管理类工作流；pi 目录下只拦真正的凭证文件（见 globs） */
const BLOCKED_FRAGMENTS = [
  "/.ssh/", "/.aws/", "/.gnupg/", "/.docker/config.json",
  "secrets/", ".kube/config",
];

/** L1：write/edit 禁写路径（完整性防护，防止模型改 pi 凭证/git 元数据）
 *  注意：不含整个 .pi/ —— 那会挡住"让 pi 改 settings.json/models.json"的正常工作流 */
const PROTECTED_WRITE_FRAGMENTS = [
  "/.ssh/", "/.git/",
  ".pi/agent/auth.json", ".pi/agent/trust.json", ".pi/agent/web-push.json",
];

/** bash/powershell 中视为"读取类"的命令词 */
const READISH = /\b(cat|less|more|head|tail|bat|type|strings|xxd|od|base64|env|printenv|set|grep|rg|awk|sed|dd|Get-Content|gc|Select-String|openssl)\b/i;

/** L2/L3：值形态脱敏规则 */
const REDACT_RULES: Array<[RegExp, string]> = [
  // 带前缀的 token
  [/\bsk-(ant-)?[A-Za-z0-9_\-]{16,}\b/g, "[REDACTED_KEY]"],
  [/\b(ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GH]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GH]"],
  [/\bglpat-[A-Za-z0-9_\-]{15,}\b/g, "[REDACTED_GITLAB]"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS]"],
  [/\bAIza[0-9A-Za-z_\-]{30,}\b/g, "[REDACTED_GOOGLE]"],
  [/\bhf_[A-Za-z0-9]{30,}\b/g, "[REDACTED_HF]"],
  [/\bsk-or-[A-Za-z0-9\-_]{20,}\b/g, "[REDACTED_OPENROUTER]"],
  // 智谱 GLM key：{32位hex}.{16位字母数字}；加 lookbehind/边界防误伤长哈希（如 git SHA）
  [/(?<![0-9a-fA-F])[0-9a-fA-F]{32}\.[A-Za-z0-9]{16}(?![A-Za-z0-9])/g, "[REDACTED_ZHIPU]"],
  // JWT
  [/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*\b/g, "[REDACTED_JWT]"],
  // 私钥块
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_KEY]"],
  // KV 赋值：兼容 env 大写形态（MY_DB_PASSWORD=xxx），跳过"引用型"值
  // （process.env.X / config.getX() / dotted 路径 / ${VAR} / <placeholder>）
  [/\b([A-Za-z0-9_]*(?:(?:API_?)?KEY|SECRET|TOKEN|PASSW(?:OR)?D|PASSPHRASE)[A-Za-z0-9_]*)\b(\s*[:=]\s*)(?!process\.env|os\.environ|\$\{|env\.|<|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(["']?)([A-Za-z0-9_\-\.\/+]{16,})\3/gi,
   "$1$2$3[REDACTED]$3"],
];

const SCAN_PAYLOAD = true;   // L3 总开关

// ======================= 实现 =======================

function redactText(text: string): string {
  let out = text;
  for (const [re, rep] of REDACT_RULES) out = out.replace(re, rep);
  return out;
}

/** 路径归一化：反斜杠→正斜杠 + 小写（Windows 大小写不敏感） */
function normPath(p: string): string {
  return p.replace(/\\/g, "/").toLowerCase();
}

function basename(p: string): string {
  const n = normPath(p);
  return n.slice(n.lastIndexOf("/") + 1);
}

function isBlockedPath(rawPath: string): string | undefined {
  const full = normPath(rawPath);
  const base = basename(rawPath);
  if (BLOCKED_BASENAMES.has(base)) return base;
  for (const re of BLOCKED_BASENAME_GLOBS) if (re.test(base)) return base;
  for (const frag of BLOCKED_FRAGMENTS) if (full.includes(frag)) return frag;
  return undefined;
}

/** L3：深度遍历 payload，替换所有字符串。返回替换的字符串个数 */
function deepRedact(node: unknown): number {
  if (typeof node === "string") return 0; // 字符串不可变，由父层处理
  if (Array.isArray(node)) {
    let n = 0;
    for (let i = 0; i < node.length; i++) {
      const v = node[i];
      if (typeof v === "string") {
        const r = redactText(v);
        if (r !== v) { node[i] = r; n++; }
      } else n += deepRedact(v);
    }
    return n;
  }
  if (node && typeof node === "object") {
    let n = 0;
    const obj = node as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (typeof v === "string") {
        const r = redactText(v);
        if (r !== v) { obj[k] = r; n++; }
      } else n += deepRedact(v);
    }
    return n;
  }
  return 0;
}

export default function (pi: ExtensionAPI) {
  // 重复拦截记账：补 loop-guard 盲区——tool_call 链式处理中首个 block 短路返回，
 // 后来者（loop-guard）看不到被我拦的调用，其重复指纹防护对这类重试失明。
 // 所以这里自己升级：同目标第 3 次拦截强化提示，第 5 次 terminate。
  const blockCounts = new Map<string, number>();
  function escalate(key: string, baseReason: string): { block: true; reason: string; terminate?: boolean } {
    const n = (blockCounts.get(key) ?? 0) + 1;
    blockCounts.set(key, n);
    if (n >= 5) return { block: true, reason: `${baseReason}（已第 ${n} 次拦截同一目标，终止本轮）`, terminate: true };
    if (n >= 3) return { block: true, reason: `${baseReason}（已第 ${n} 次拦截：不要重试，直接向用户说明需要该内容的原因，或请用户手动提供脱敏后版本）` };
    return { block: true, reason: baseReason };
  }

  // ============ L1：执行前拦截 ============
  pi.on("tool_call", async (event, ctx) => {
    const input = event.input as Record<string, unknown>;

    // 文件类读取工具：只查 path 字段（grep/find 的 pattern/glob 是搜索式，不拦，
    // grep/find 本身遵守 .gitignore，内容泄露由 L2/L3 兜底）
    if (event.toolName === "read" || event.toolName === "ls") {
      const hit = isBlockedPath(String(input.path ?? ""));
      if (hit) {
        if (ctx.hasUI) ctx.ui.notify(`Blocked sensitive path: ${hit}`, "warning");
        return escalate(`read:${hit}`, `"${hit}" 在敏感清单中，读取已阻止`);
      }
    }

    // shell 类（bash + powershell，Windows 下两个都存在）
    if (event.toolName === "bash" || event.toolName === "powershell") {
      const cmd = String(input.command ?? "");
      const normalized = normPath(cmd);
      const hit = BLOCKED_FRAGMENTS.find((f) => normalized.includes(f))
        ?? [".env", ".pem", ".key", "id_rsa", "id_ed25519", "auth.json", "credentials"]
            .find((f) => normalized.includes(f));
      if (hit && READISH.test(cmd)) {
        if (ctx.hasUI) ctx.ui.notify(`Blocked shell read of: ${hit}`, "warning");
        return escalate(`shell:${hit}`, `shell 命令疑似读取敏感文件 (${hit})`);
      }
    }

    // 写入类：防篡改（防止模型改 pi 凭证/git 元数据）
    if (event.toolName === "write" || event.toolName === "edit") {
      const p = normPath(String(input.path ?? ""));
      const hit = PROTECTED_WRITE_FRAGMENTS.find((f) => p.includes(f));
      if (hit) {
        if (ctx.hasUI) ctx.ui.notify(`Blocked write to: ${p}`, "warning");
        return escalate(`write:${hit}`, `"${p}" 受写保护`);
      }
    }

    return undefined;
  });

  // ============ L2：执行后脱敏（落盘会话也被保护） ============
  pi.on("tool_result", async (event) => {
    let changed = false;
    const newContent = event.content.map((part) => {
      if (part.type !== "text") return part;
      const r = redactText(part.text);
      if (r !== part.text) changed = true;
      return { ...part, text: r };
    });
    return changed ? { content: newContent } : undefined;
  });

  // ============ L3：出站前扫描整个 payload ============
  // 与 secret-scan.ts 同 hook：那个扩展只告警不改，这个改。
  // 若本文件名字母序在 secret-scan 之前（默认 e < s），它会先看到脱敏后的
  // payload 而不再告警（其 isRedacted 认得 [REDACTED] 占位）。
  // 建议安装时改名为 z-egress-guard.ts：让 secret-scan 先扫（原始告警）
  // 本扩展后脱敏（防护），观测与防护双全；下面的 notify 兜底两种顺序都成立。
  if (SCAN_PAYLOAD) {
    pi.on("before_provider_request", async (event, ctx) => {
      const n = deepRedact(event.payload);
      if (n > 0 && ctx.hasUI && ctx.ui?.notify) {
        ctx.ui.notify(`egress-guard: 出站请求中发现并脱敏 ${n} 处敏感串`, "warning");
      }
      return event.payload;
    });
  }
}
