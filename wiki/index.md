# Wiki Index

<!-- LLM 维护的内容索引。每个页面一行：链接 + 单行摘要 -->

## Overview

- [Overview](overview.md) — 项目全景：目标、范围、当前状态

## Architecture

<!-- 架构笔记在 C2–C6 checkpoint 实现后逐步填充 -->
- [Pipeline Stages](architecture/pipeline-stages.md) — search / fetch / scan / dedup / report 每阶段（待写）
- [Concurrency](architecture/concurrency.md) — 并发分层与 rate limit 策略（待写）
- [State Storage](architecture/state-storage.md) — orphan state 分支协议（待写）

## Vendors

<!-- 每个厂商一篇 vendor page，在 C2 实现 rules.rs 后批量创建 -->

## Decisions (ADR)

- [0001 — Rust over Python](decisions/0001-rust-over-python.md) — 为什么从 Python 单文件重写到 Rust（待写）

## Incidents

<!-- 运行时遇到的 false positive / rate limit / ToS 事件在此记录 -->
- [2026-04 AWS example-key FP](incidents/2026-04-aws-example-key-fp.md) — 误报 AKIAIOSFODNN7EXAMPLE 触发目标仓库 maintainer 关闭，已加 `src/filters.rs` allowlist
