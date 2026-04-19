# Wiki Log

<!-- Append-only。每条以 `## [YYYY-MM-DD] operation | description` 开头 -->

## [2026-04-19] init | Wiki 初始化

创建 `SCHEMA.md`、`wiki/index.md`、`wiki/log.md`、`wiki/overview.md`。项目同时启动从 Python 单文件 (`leak_scanner.py`) 向 Rust + 多厂商 + GitHub Action 的重构。GAN 模式 team `gan-leak-scanner` 已建立，checkpoint C1–C6 入 task list。

## [2026-04-19] ingest | Rust 重构完成（C1–C6）

Rust crate 落地：
- `src/rules.rs`：20 条规则，8 个 Tier A（Anthropic/OpenAI/Google AI/Groq/HF/Replicate/xAI/Perplexity）+ 12 条 Tier B（AWS + 6 个 GitHub PAT 变体 + 2 个 Stripe + 3 个 Slack）。6 个 Tier A 厂商（Mistral/Cohere/DeepSeek/Together/Fireworks/Azure OpenAI）因 prefix 无区分度延后。
- `src/redact.rs`：`prefix_len_for(len) = min(8, len/4)` 确保熵泄漏下限。
- `src/github.rs` + `src/ratelimit.rs`：reqwest + governor + reqwest-retry；search 10/min，REST 80/min（5000/hr 以下）。
- `src/scan.rs`：三阶段 pipeline，`buffer_unordered(128)` 并发 blob fetch，`RegexSet` 单遍匹配。
- `src/state.rs` + `src/issue.rs` + `src/main.rs`：clap 三子命令；`(repo, rule_id)` 去重；`--confirm` 门槛 + 30s spacing + 5/run cap。
- `.github/workflows/scan.yml`：cron `17 */3 * * *`；orphan `state` 分支保存 `reported.json` 和 `findings/YYYY-MM-DD.ndjson`；披露邮件 draft 作为 artifact。

GAN 审查：C2、C5 各经过 round-2 修复（redact 熵泄漏、within-run dedup）后 PASS；C3、C4 一次 PASS。`.review/log.md` 留下 4 条跨 checkpoint pattern。

未来 ingest 工作：
- 为每个厂商写 `wiki/vendors/<id>.md`（引用源 + 已知 FP pattern + 披露 channel）
- 写 `wiki/architecture/pipeline-stages.md` / `concurrency.md` / `state-storage.md`
- 写 `wiki/decisions/0001-rust-over-python.md` ADR
- 写 `wiki/vendors/_deferred.md` 记录延后的 6 个 Tier A 厂商及原因
