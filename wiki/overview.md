---
title: Overview
type: overview
updated: 2026-04-19
---

# Overview

## 目标

在 GitHub 公共代码中扫描多厂商 API key 泄漏（LLM / 云 / SaaS），以负责任披露方式通知仓库主。定期自动化运行。

## 三阶段演化

| 阶段 | 形态 | 状态 |
|------|------|------|
| v0 | Python 单文件 `leak_scanner.py`，Anthropic only，手动 CLI | 已完成，保留作参考 |
| v1 | Rust CLI，Tier A+B 共 20 条规则（12 vendor 家族），GitHub Action 定时跑 | **进行中（本次重构）** |
| v2 | 可能扩展：GitHub App、更多厂商、熵检测、私仓支持 | 未排期 |

## v1 范围

**总计 20 条规则，覆盖 12 个 vendor 家族**（`src/rules.rs` 是 source of truth）：

- **Tier A 已支持（8 个 LLM/AI 厂商，每家一条规则）**：Anthropic、OpenAI (`T3BlbkFJ` anchor，含 `sk-proj-`/`sk-svcacct-`/`sk-admin-`)、Google AI (`AIza`)、Groq (`gsk_`)、HuggingFace (`hf_`)、Replicate (`r8_`)、xAI (`xai-`)、Perplexity (`pplx-`)
- **Tier A 延后（6 个无可靠 regex prefix）**：Mistral、Cohere、DeepSeek、Together、Fireworks、Azure OpenAI——这些厂商的 key 没有区分度高的固定前缀，v1 用纯 regex 扫会产生大量误报。详见 `wiki/vendors/_deferred.md`（待写）。未来可能靠 keyword + 熵检测引入
- **Tier B 云/SaaS（4 家族，12 条规则）**：AWS (`AKIA`/`ASIA`/`AROA`/`AIDA`)、GitHub PAT (6 个变体：`ghp_`/`github_pat_`/`ghs_`/`gho_`/`ghu_`/`ghr_`)、Stripe (`sk_live_` + `rk_live_`)、Slack (`xoxb-`/`xoxp-`/`xapp-`)

共 8 + 12 = **20 条有效 regex 规则**，每条独立搜索 query，一轮扫描预估 search API 开销 ≤ 20 req → 2 分钟 + 分页。

**调度**：GitHub Action，每 3 小时一次（cron `17 */3 * * *`）

**并发分层**：
- Search API 硬限 10 req/min → 串行 + token bucket
- Blob fetch → `Semaphore(128)` + `buffer_unordered`
- Issue 开单 → 反而要慢，30s spacing

**持久化**：同仓 orphan `state` 分支保存 `reported.json`（`(repo, vendor)` 去重键）和 `findings/YYYY-MM-DD.ndjson`（审计日志）

**披露**：
1. 每个受影响仓库开 ONE issue（已 dedup、5/run、30s spacing）
2. 每个 vendor 生成邮件 draft 作为 artifact，**不自动发**，盖尔人工审阅

## 硬约束（非协商项）

- 永不调用 vendor API 验证发现的 key
- 永不持久化或打印完整 key（只留 prefix[:16] + sha256[:8] + length）
- 每个 (repo, vendor) 一辈子只开一次 issue
- 无 `--confirm` flag 绝不开 issue

## 关键风险

- **Rate limit**：search 10/min 很紧，一轮 Tier A+B 扫完预估 8–12 分钟
- **False positive**：部分厂商（Mistral / xAI / DeepSeek 等）prefix 未公开，只能靠 keyword + 熵判断，confidence 标 low
- **Vendor 关系**：如果自动开的 issue 被仓库主认为是骚扰，可能被 GitHub 判滥用；因此保留仓库 cap + spacing

## 阅读路线

- 想理解某厂商 regex → `wiki/vendors/<vendor>.md` + `src/rules.rs`
- 想理解并发/速率 → `wiki/architecture/concurrency.md`
- 想理解去重 → `wiki/architecture/state-storage.md`
- 想理解为什么用 Rust → `wiki/decisions/0001-rust-over-python.md`
