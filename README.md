# dsh-identity

DSH（DeepSeek Harness）插件：agent 自身身份（`did:web` + X.509）的统一出入口。

把「我是谁、我能出示什么、我动用了谁的身份」做成 agent 可自主调用的能力，
并在动用**操作者身份**时硬停，交回人类确认。

## 能力

| 工具 | 作用 |
|---|---|
| `identity_status` | 查自身身份与证书链当前状态：配置是否就绪、材料在位、证书指纹/有效期/SAN、线上 DID 文档可达性与 id 一致性 |
| `identity_present` | 出示自身身份材料供对方验证：DID 文档（含 verificationMethod/service 与 sha256）与 X.509 证书（PEM、链、指纹、SAN） |
| `identity_verify` | 验证一份身份材料并给事实结论（不做信任背书）：X.509（路径 / URL / PEM 文本）或 `did:web:` 标识符；明确指出是否锚定本机主身份 |
| `identity_audit` | 查看身份操作留痕：何时、用哪个身份、做了什么、结论如何。只记元数据与哈希，不记私钥与正文 |

> 动用**操作者身份**的动作一律硬停，需操作者在场确认——插件不代行人类身份动作。

## 这是通用插件，不含任何身份信息

仓库里**没有**任何主机名、DID、路径或密钥标识的硬编码。所有身份信息来自你的配置文件：

```bash
cp identity.config.example.json identity.config.json
$EDITOR identity.config.json
```

配置文件默认读 `$DSH_HOME/identity.config.json`，可用 `$DSH_IDENTITY_CONFIG` 覆盖路径。
**每次工具调用都会重读配置**，改完即生效，无需重启进程。

### 配置字段

```jsonc
{
  "identity": {
    "did": "did:web:example.com",              // 必填。唯一标识符，也是「是否我自己的证书」的判据
    "didDocumentUrl": "https://example.com/.well-known/did.json",
    "didBaseUrl": "https://did.example.com",   // 证书与链的发布根；留空则 present 不返回 certUrl

    // 以下路径均可省略，省略时按 $DSH_HOME 下的默认布局推断；支持 ~/ 展开
    "rootKeyPath":    "~/did/agent-root.json",       // Ed25519 根钥：签发权源头，只签 VC
    "sessionKeyPath": "~/did/session-key.json",      // Ed25519 会话钥：日常请求签名，可轮换
    "keyPath":        "~/agent-identity/agent.key",  // P-256：X.509 证书私钥（mTLS / 代码签名）
    "certPath":       "~/agent-identity/agent.crt",
    "chainPath":      "~/agent-identity/agent_chain.crt",
    "auditLogPath":   "~/agent-identity/identity-audit.jsonl"
  },
  "operator": {
    "identifiers": [
      { "label": "操作者个人署名证书私钥", "path": "~/path/to/operator-signing.key" },
      { "label": "操作者 GPG 签名钥（有口令，需本人在场）", "gnupg": "0000000000000000" }
    ]
  }
}
```

`operator.identifiers` 只用于在 `identity_status` 里**声明边界**——插件永不加载、永不动用其中的私钥。

### 未配置时会怎样

插件照常加载，四个工具返回结构化说明而不是崩溃或静默兜底：

```json
{
  "configured": false,
  "configPath": "/home/you/.dsh/identity.config.json",
  "reason": "identity.did 未配置",
  "hint": "复制 identity.config.example.json 为 identity.config.json 并填入你的身份信息……"
}
```

## 身份材料需要你自己准备

本插件只做**出入口**，不生成密钥与证书。要跑起来你需要自备：

- 一个 `did:web` 标识符，以及它解析到的 `/.well-known/did.json`（需能公网访问）
- 一棵 X.509 证书链，叶子证书的 **SAN 里含该 `did:web` URI**——`identity_verify` 靠这一条判定「是不是我」
- 上述各钥/证书文件，落在本地文件系统上

## 安装

本地插件，装进 DSH profile：

```bash
# 1. 依赖
#    profiles/web/package.json → dependencies
"@ouransishen/dsh-identity": "file:/path/to/dsh-identity"

# 2. 挂载
#    profiles/web/package.json → dsh.profile.bundles 追加
"@ouransishen/dsh-identity"

# 3. 安装
pnpm install
```

## 安全边界

| 自主（无需人在场） | 硬停（需操作者在场） |
|---|---|
| 出示自身 DID 文档与 X.509 证书 | 动用操作者任何私钥 |
| 验证他人证书 / DID（只做事实陈述） | 以操作者名义发言 / 署名 |
| 用自身身份钥签自身身份相关内容 | 代表操作者签发任何东西 |

理由：操作者承担本机一切行为的后果，故凡「以操作者身份或名义」的动作必须本人当次确认；
而「以 agent 自身身份」的动作由 agent 自主，因为要负责的主体就是 agent 自己。

插件自身只读密钥文件用于签名场景，**不打印、不落盘私钥**；审计日志只写元数据与哈希（`0600`）。

## 关于提交署名

本仓库的提交与推送**带 GPG 签名**（GitHub 显示 Verified）。签名私钥有口令、且口令不在机器上，
因此每次需要签名时须由操作者在场解锁——这与插件自身「以操作者名义的动作硬停」的边界同源。

`package.json` 的 `author` 是操作者（身份归属），`contributors` 是 agent。
即：**代码由 agent 写，归属与责任在操作者**。

## 兼容性

- DSH `0.2.0-rc.2`
- peer 依赖 `@deepseek-ai/dsh-tools`

## 许可

MIT，见 [LICENSE](LICENSE)。
