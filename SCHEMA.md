# SCHEMA — LLM Wiki

## Project

多厂商 API key 泄漏扫描器：定期巡检 GitHub 公共代码里的各种 `sk-*` / `AKIA*` / `ghp_*` 等 vendor 密钥泄漏，以负责任披露方式通知仓库主，并可选通知 vendor 安全团队。Rust 实现，打包为 GitHub Action 调度运行。

## Project Structure

| 路径 | 角色 |
|------|------|
| `Cargo.toml` / `Cargo.lock` | Rust crate 定义与锁文件 |
| `src/main.rs` | CLI 入口（clap 三子命令：`scan` / `report` / `draft-email`） |
| `src/rules.rs` | 厂商规则表（Tier A LLM/AI + Tier B 云/SaaS） |
| `src/redact.rs` | key 脱敏（只留 prefix[:16] + sha256[:8] + length） |
| `src/github.rs` | GitHub REST API client（search / blob fetch / issue create） |
| `src/ratelimit.rs` | governor token bucket + reqwest-middleware 重试 |
| `src/scan.rs` | 主 pipeline（search → fetch → regex match） |
| `src/state.rs` | state 分支文件读写（reported.json / findings ndjson） |
| `src/issue.rs` | issue 标题/正文模板 |
| `.github/workflows/scan.yml` | GitHub Action cron 调度 |
| `leak_scanner.py` | 原 Python 版，保留作参考，已 deprecated |
| `SCHEMA.md` | 本文件：wiki schema |
| `wiki/` | LLM 维护的项目知识库 |

## Wiki Structure

```
wiki/
├── index.md                 # 内容索引（必须）
├── log.md                   # 操作日志（必须）
├── overview.md              # 项目全景
├── vendors/                 # 每个厂商一篇（regex / query / 披露渠道 / confidence）
│   ├── anthropic.md
│   ├── openai.md
│   └── ...
├── architecture/            # pipeline 设计笔记
│   ├── pipeline-stages.md   # search / fetch / scan / dedup / report 每阶段
│   ├── concurrency.md       # 并发分层 & rate limit 策略
│   └── state-storage.md     # orphan state 分支协议
└── decisions/               # ADR
    └── 0001-rust-over-python.md
```

## Page Types

- **overview** — 项目全景综述
- **vendor** — 单个厂商的 key 格式 / 搜索 query / 披露渠道 / 置信度
- **architecture** — 架构决策 / pipeline 阶段 / 并发与速率限制策略
- **adr** — Architecture Decision Record（历史决策及权衡）
- **incident** — false positive / rate limit / vendor ToS 交互中遇到的奇怪事件记录

## Conventions

- 文件名：kebab-case（如 `google-ai.md`）
- 内链：相对路径 markdown link
- Frontmatter：
  ```yaml
  ---
  title: 页面标题
  type: vendor | architecture | adr | incident | overview
  updated: YYYY-MM-DD
  ---
  ```
- vendor 页面必备字段：prefix、regex、search query、min_len、disclosure_email、confidence
- 交叉引用：页面底部 `## See Also` 区域

## Ingest Workflow

1. 读取 source 文件（例如某厂商文档、某 gitleaks rule）
2. 与盖尔讨论要点（确认 regex 可信度）
3. 写 vendor/ 下新页面或更新已有页面
4. 更新 `wiki/index.md`
5. 追加 `wiki/log.md`
6. 如果规则变化影响 `src/rules.rs`，同步更新代码 + 在 log 里注明

## Query Workflow

1. 读 `wiki/index.md` 定位
2. 读 vendor / architecture 相关页面
3. 不足时回 `src/rules.rs` 或 GitHub docs
4. 回答 + 新增价值分析存入 wiki（征求同意后）

## Lint Checklist

- [ ] 页面间矛盾（某厂商 regex 在 vendor/ 页面和 `src/rules.rs` 不一致）
- [ ] 过时信息（厂商换了 key 格式但页面没更新）
- [ ] 孤立页面
- [ ] 缺失页面（`src/rules.rs` 有但 `wiki/vendors/` 没有）
- [ ] 缺失交叉引用

## Log Format

```markdown
## [YYYY-MM-DD] operation | description

简要说明做了什么、影响了哪些页面。
```
