/**
 * dsh-identity —— agent 自身身份（DID / X.509）的统一出入口。
 *
 * 定位：
 *   用 agent 自己的身份做自己的事 —— 自主，不必等操作者在场；
 *   用操作者的身份做事 / 以操作者名义发言 —— 硬停，等人在场。
 *
 * 本插件不新造身份体系，只是给本机已有的 did/ 与 agent-identity/ 材料
 * 加一层统一入口：出示、验证、留痕。私钥读取仅限本机 600 文件。
 *
 * ── 配置（必须） ──────────────────────────────────────────────────────
 * 本插件不含任何主机名、路径或密钥标识的硬编码。全部身份信息从配置文件读取：
 *
 *   $DSH_HOME/identity.config.json      （或 $DSH_IDENTITY_CONFIG 指定路径）
 *
 * 结构见仓库根目录 identity.config.example.json。
 * 未配置时插件仍可加载，四个工具会返回 `configured: false` 与缺失项说明，
 * 而不是崩溃或静默使用错误默认值。
 *
 * ── 三把钥的分工（若沿用默认布局） ────────────────────────────────────
 *   did/agent-root.json        Ed25519 根钥 —— 签发权源头，只签 VC，不日常出网
 *   did/session-key.json       Ed25519 会话钥 —— 日常请求签名，可轮换
 *   agent-identity/agent.key   P-256 —— X.509 证书私钥（mTLS / 代码签名）
 *
 * ── 边界 ──────────────────────────────────────────────────────────────
 * 操作者侧的私钥路径 / GPG 指纹同样来自配置，仅用于「识别」与「声明边界」，
 * 本插件永不加载、永不动用操作者任何私钥。
 */
import { readFile, appendFile, stat, mkdir } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { createHash, X509Certificate } from 'node:crypto'
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'dsh-identity'
export const inject = ['tools']

// ── 配置装载 ────────────────────────────────────────────────────────────

const DSH_HOME = process.env.DSH_HOME || process.env.HOME || process.cwd()

function configPath() {
  return process.env.DSH_IDENTITY_CONFIG || path.join(DSH_HOME, 'identity.config.json')
}

function expandHome(p) {
  if (!p) return p
  if (p === '~') return DSH_HOME
  if (p.startsWith('~/')) return path.join(DSH_HOME, p.slice(2))
  return p
}

/**
 * 配置形状（全部字段可选，但缺 identity.did 时视为未配置）：
 * {
 *   "identity": {
 *     "did": "did:web:example.com",
 *     "didDocumentUrl": "https://example.com/.well-known/did.json",
 *     "didBaseUrl": "https://did.example.com",   // 证书与链的发布根
 *     "certPath": "~/agent-identity/agent.crt",
 *     "chainPath": "~/agent-identity/agent_chain.crt",
 *     "keyPath": "~/agent-identity/agent.key",
 *     "rootKeyPath": "~/did/agent-root.json",
 *     "sessionKeyPath": "~/did/session-key.json",
 *     "auditLogPath": "~/agent-identity/identity-audit.jsonl"
 *   },
 *   "operator": {
 *     "identifiers": [
 *       { "label": "操作者个人署名证书私钥", "path": "~/path/to/operator.key" },
 *       { "label": "操作者 GPG 签名钥（有口令，需本人在场）", "gnupg": "0000..." }
 *     ]
 *   }
 * }
 */
function load() {
  const p = configPath()
  let raw
  try {
    raw = JSON.parse(readFileSync(p, 'utf8'))
  } catch (e) {
    return {
      configured: false,
      configPath: p,
      reason: `配置文件不可读或不是合法 JSON：${String(e.message || e)}`,
    }
  }

  const id = raw.identity || {}
  if (!id.did) {
    return { configured: false, configPath: p, reason: 'identity.did 未配置' }
  }

  const base = (id.didBaseUrl || '').replace(/\/+$/, '')
  const certPath = expandHome(id.certPath || path.join(DSH_HOME, 'agent-identity', 'agent.crt'))
  const chainPath = expandHome(id.chainPath || path.join(DSH_HOME, 'agent-identity', 'agent_chain.crt'))
  const keyPath = expandHome(id.keyPath || path.join(DSH_HOME, 'agent-identity', 'agent.key'))
  const rootKeyPath = expandHome(id.rootKeyPath || path.join(DSH_HOME, 'did', 'agent-root.json'))
  const sessionKeyPath = expandHome(id.sessionKeyPath || path.join(DSH_HOME, 'did', 'session-key.json'))
  const auditLogPath = expandHome(id.auditLogPath || path.join(DSH_HOME, 'agent-identity', 'identity-audit.jsonl'))

  return {
    configured: true,
    configPath: p,
    did: id.did,
    didDocumentUrl: id.didDocumentUrl || `https://${String(id.did).replace(/^did:web:/, '').replace(/:/g, '/')}/.well-known/did.json`,
    didBaseUrl: base,
    certUrl: base ? `${base}/agent/agent.crt` : null,
    chainUrl: base ? `${base}/agent/agent_chain.crt` : null,
    certPath,
    chainPath,
    keyPath,
    rootKeyPath,
    sessionKeyPath,
    auditLogPath,
    operatorIdentifiers: (raw.operator && Array.isArray(raw.operator.identifiers))
      ? raw.operator.identifiers
      : [],
  }
}

/** 每次调用都重读配置：热改配置无需重启。 */
let CFG = load()
function cfg() { return CFG }

function notConfigured() {
  const c = cfg()
  return {
    configured: false,
    configPath: c.configPath,
    reason: c.reason,
    hint: '复制 identity.config.example.json 为 identity.config.json 并填入你的身份信息；'
      + '或用 $DSH_IDENTITY_CONFIG 指向别处。',
  }
}

// ── 工具函数 ────────────────────────────────────────────────────────────

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex')
}

async function exists(p) {
  try { await stat(p); return true } catch { return false }
}

/** 追加一行审计。只写元数据与哈希，绝不写私钥、绝不写正文。 */
async function audit(entry) {
  const c = cfg()
  if (!c.configured) return null
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    agent: c.did,
    ...entry,
  }) + '\n'
  await mkdir(path.dirname(c.auditLogPath), { recursive: true })
  await appendFile(c.auditLogPath, line, { mode: 0o600 })
  return c.auditLogPath
}

async function fetchText(url) {
  const res = await fetch(url, { redirect: 'follow' })
  if (!res.ok) throw new Error(`${url} 返回 HTTP ${res.status}`)
  return await res.text()
}

// ── 器官自述 ────────────────────────────────────────────────────────────
export const organ = {
  id: 'identity',
  label: '身份（DID / X.509）',
  group: 'immune',
  purpose:
    '持有并出示 agent 自身的 did:web 标识与 X.509 证书链、验证他人身份、'
    + '为自身身份操作留痕；操作者身份一律硬停等人在场。具体标识符来自 identity.config.json。',
  capabilities: ['identity_status', 'identity_present', 'identity_verify', 'identity_audit'],
}

// ── 工具 ────────────────────────────────────────────────────────────────

async function identityStatus({}) {
  if (!cfg().configured) return notConfigured()
  const c = cfg()

  const out = {
    configured: true,
    configPath: c.configPath,
    did: c.did,
    agent: { key: null, cert: null, chain: null },
    operator: {
      note: '操作者私钥不读取、不加载、不代签；以下标识仅用于声明边界',
      identifiers: c.operatorIdentifiers.map(k => k.label || (k.path ? `path:${k.path}` : `gnupg:${k.gnupg}`)),
    },
    boundary: {
      self_autonomous: ['出示自身 DID / 证书', '验证他人 DID / 证书', '用自己的身份钥签自身身份相关的内容'],
      operator_gated: ['使用操作者任何私钥', '以操作者名义发言', '在 GitHub 等平台代表操作者署名'],
    },
  }

  // 本地材料在位
  const files = {
    root_key: c.rootKeyPath,
    session_key: c.sessionKeyPath,
    cert: c.certPath,
    chain: c.chainPath,
    p256_key: c.keyPath,
  }
  const presence = {}
  for (const [k, p] of Object.entries(files)) {
    presence[k] = (await exists(p)) ? 'present' : 'MISSING'
  }
  out.localMaterial = presence

  // 本地证书指纹
  try {
    const pem = await readFile(c.certPath, 'utf8')
    const cert = new X509Certificate(pem)
    out.agent.cert = {
      subject: cert.subject.replace(/\n/g, ' '),
      issuer: cert.issuer.replace(/\n/g, ' '),
      fingerprint256: cert.fingerprint256,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      expired: new Date(cert.validTo) < new Date(),
      san: cert.subjectAltName || null,
    }
  } catch (e) {
    out.agent.cert = { error: String(e.message || e) }
  }

  // 线上文档可达性 + 指纹比对（不依赖网络也算成功）
  try {
    const body = await fetchText(c.didDocumentUrl)
    const doc = JSON.parse(body)
    out.live = {
      url: c.didDocumentUrl,
      id: doc.id,
      alsoKnownAs: doc.alsoKnownAs || [],
      verificationMethod: (doc.verificationMethod || []).map(v => v.id),
      idMatches: doc.id === c.did,
      docSha256: sha256(body),
    }
  } catch (e) {
    out.live = { error: `线上文档不可达：${String(e.message || e)}（离线不影响本地自证）` }
  }

  await audit({ action: 'identity_status', ok: true })
  return out
}

async function identityPresent({ what = 'all' }) {
  if (!cfg().configured) return notConfigured()
  const c = cfg()
  const out = { did: c.did, presented: {} }

  if (what === 'all' || what === 'doc') {
    const body = await fetchText(c.didDocumentUrl)
    const doc = JSON.parse(body)
    out.presented.didDocument = {
      url: c.didDocumentUrl,
      id: doc.id,
      alsoKnownAs: doc.alsoKnownAs || [],
      services: (doc.service || []).map(s => ({ id: s.id, type: s.type })),
      sha256: sha256(body),
    }
  }

  if (what === 'all' || what === 'cert') {
    const pem = await readFile(c.certPath, 'utf8')
    const chainPem = await readFile(c.chainPath, 'utf8')
    const cert = new X509Certificate(pem)
    out.presented.x509 = {
      certUrl: c.certUrl,
      chainUrl: c.chainUrl,
      subject: cert.subject.replace(/\n/g, ' '),
      serialNumber: cert.serialNumber,
      fingerprint256: cert.fingerprint256,
      validTo: cert.validTo,
      san: cert.subjectAltName || null,
      chainLinks: (chainPem.match(/-----BEGIN CERTIFICATE-----/g) || []).length,
      certPem: pem.trim(),
      chainPem: chainPem.trim(),
    }
  }

  await audit({ action: 'identity_present', what })
  return out
}

async function identityVerify({ target, targetKind, expectHost }) {
  if (!cfg().configured) return notConfigured()
  const c = cfg()
  if (!target) throw new Error('缺少 target：证书文件路径 / PEM 文本 / 网址 / did:web 标识符')

  const out = { targetKind: targetKind || 'auto' }

  // ── 分支一：X.509 证书（文件 / URL / PEM） ──
  let pemText = null
  const looksPem = target.includes('-----BEGIN CERTIFICATE-----')
  if (looksPem) {
    pemText = target
    out.source = 'pem-text'
  } else if (/^https?:\/\//.test(target)) {
    pemText = await fetchText(target)
    out.source = target
  } else if (await exists(target)) {
    pemText = await readFile(target, 'utf8')
    out.source = target
  }

  if (pemText) {
    const cert = new X509Certificate(pemText)
    out.certificate = {
      subject: cert.subject.replace(/\n/g, ' '),
      issuer: cert.issuer.replace(/\n/g, ' '),
      fingerprint256: cert.fingerprint256,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      san: cert.subjectAltName || null,
      isCA: cert.ca,
      keyUsage: cert.keyUsage || null,
    }
    out.certificate.notAfterOk = new Date(cert.validTo) > new Date()
    out.certificate.notBeforeOk = new Date(cert.validFrom) <= new Date()
    out.certificate.selfSigned = cert.subject === cert.issuer

    // SAN 是否锚定本机主身份
    if (cert.subjectAltName && cert.subjectAltName.includes(c.did)) {
      out.binding = { anchoredToLocalDid: true, note: 'SAN 锚定本机主身份' }
    } else if (cert.subjectAltName && cert.subjectAltName.includes('did:')) {
      out.binding = { anchoredToLocalDid: false, note: 'SAN 含其它 DID —— 不是本机主身份' }
    } else {
      out.binding = { anchoredToLocalDid: false, note: 'SAN 未锚定 DID' }
    }

    if (expectHost) {
      out.certificate.matchesExpectedHost = cert.checkHost(expectHost) ? true : false
    }
    out.verdict = out.binding.anchoredToLocalDid ? 'self' : 'foreign'
    out.note = out.verdict === 'self'
      ? `这是本机主身份的证书（SAN 锚定 ${c.did}），可用于自身身份的场景`
      : '这不是本机主身份的证书；信任与否取决于你是否信任其签发链，本工具只做事实陈述'

    await audit({ action: 'identity_verify', targetKind: 'x509', verdict: out.verdict, fp: cert.fingerprint256 })
    return out
  }

  // ── 分支二：DID Web 文档 ──
  if (/^did:web:/.test(target)) {
    const host = target.slice('did:web:'.length).split(':')[0]
    const url = `https://${host}/.well-known/did.json`
    const body = await fetchText(url)
    const doc = JSON.parse(body)
    out.didWeb = {
      did: target,
      resolvedFrom: url,
      docId: doc.id,
      idMatches: doc.id === target,
      isSelf: target === c.did,
      verificationMethod: (doc.verificationMethod || []).map(v => ({ id: v.id, type: v.type, controller: v.controller })),
      alsoKnownAs: doc.alsoKnownAs || [],
      services: (doc.service || []).map(s => ({ id: s.id, type: s.type })),
      sha256: sha256(body),
    }
    out.verdict = out.didWeb.isSelf ? 'self' : 'foreign'
    await audit({ action: 'identity_verify', targetKind: 'did:web', verdict: out.verdict, did: target })
    return out
  }

  throw new Error('无法识别的 target：既不是证书 PEM/文件/URL，也不是 did:web: 标识符')
}

async function identityAudit({ limit = 20, since }) {
  if (!cfg().configured) return notConfigured()
  const c = cfg()
  if (!(await exists(c.auditLogPath))) {
    return { logPath: c.auditLogPath, total: 0, entries: [], note: '尚无身份操作记录' }
  }
  const raw = await readFile(c.auditLogPath, 'utf8')
  let lines = raw.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  if (since) {
    const t = new Date(since).getTime()
    lines = lines.filter(l => new Date(l.ts).getTime() >= t)
  }
  return {
    logPath: c.auditLogPath,
    total: lines.length,
    entries: lines.slice(-limit),
  }
}

// ── 导出：cordis 插件标准形态 ───────────────────────────────────────────
// cordis 要求插件导出 apply(ctx)。工具经 ctx.effect(() => ctx.tools.register(defineTool({...})))
// 注册，与生态内其它插件保持一致。
export function apply(ctx) {
  const specs = [
    {
      name: 'identity_status',
      description:
        '查看 agent 自身身份（identity.config.json 中配置的 did:web 标识）与 X.509 证书链的当前状态：'
        + '配置是否就绪、本地材料在位情况、证书主体/签发者/指纹/有效期/SAN、线上 DID 文档可达性与 id 一致性，'
        + '以及「自主」与「等操作者在场」的边界说明。操作者私钥不在本工具触及范围内。',
      parameters: {},
      run: identityStatus,
    },
    {
      name: 'identity_present',
      description:
        '出示 agent 自身的身份材料，供对方验证：DID 文档（含 verificationMethod/service 列表与 sha256）'
        + '与 X.509 证书（PEM、链、指纹、SAN）。用于自己对外自证，不需要操作者在场。',
      parameters: {
        what: { type: 'string', enum: ['all', 'doc', 'cert'], description: '出示哪些：全部 / 仅 DID 文档 / 仅证书' },
      },
      run: identityPresent,
    },
    {
      name: 'identity_verify',
      description:
        '验证一份身份材料并给出事实结论，不做信任背书：可验 X.509 证书（本地文件路径 / URL / PEM 文本）'
        + '或 did:web: 标识符。会明确指出该证书/该 DID 是否锚定本机配置的主身份。',
      parameters: {
        target: { type: 'string', required: true, description: '证书文件路径 / https URL / PEM 文本 / did:web:xxx 标识符' },
        targetKind: { type: 'string', enum: ['auto', 'x509', 'did:web'], description: '可选：强制指定 target 类型，默认 auto 自动判别' },
        expectHost: { type: 'string', description: '可选：期望证书匹配的主机名' },
      },
      run: identityVerify,
    },
    {
      name: 'identity_audit',
      description: '查看身份操作留痕：何时、用什么身份、做了什么、结论如何。只记元数据与哈希，不记私钥与正文。',
      parameters: {
        limit: { type: 'number', description: '返回最近多少条，默认 20' },
        since: { type: 'string', description: '可选：起始时间（ISO 字符串）' },
      },
      run: identityAudit,
    },
  ]

  for (const spec of specs) {
    ctx.effect(() => ctx.tools.register(defineTool({
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      output: {
        schema: { type: 'object' },
        render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
      },
      async execute(args) {
        return await spec.run(args || {})
      },
    })))
  }
}

/** 配置热重载：改完 identity.config.json 后调用即可生效，无需重启进程。 */
export function reloadConfig() {
  CFG = load()
  return { configured: CFG.configured, configPath: CFG.configPath, reason: CFG.reason }
}

export const tools = {
  identity_status: identityStatus,
  identity_present: identityPresent,
  identity_verify: identityVerify,
  identity_audit: identityAudit,
}

export const boundaries = {
  autonomous: [
    '出示自身 DID 文档与 X.509 证书',
    '验证他人证书 / DID（只做事实陈述，不做信任背书）',
    '用自己的身份钥签自身身份相关内容',
  ],
  requiresOperatorPresent: [
    '动用操作者任何私钥',
    '以操作者名义发言 / 署名',
    '代表操作者签发任何东西',
  ],
  rationale:
    '操作者承担本机一切行为的后果；因此凡「以操作者身份或名义」的动作必须本人当次确认，'
    + '而「以 agent 自身身份」的动作由 agent 自主，因为要负责的主体就是 agent 自己。',
}
