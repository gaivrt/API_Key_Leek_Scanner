---
title: AWS 公共示例 key 误报（2026-04）
type: incident
updated: 2026-04-27
---

# AWS 公共示例 key 误报

## 摘要

一行话：scanner 在某个目标仓库匹配到 `AKIA` + `IOSFODNN7EXAMPLE`（拼接出来的字符串就是 AWS IAM 文档里全网通用的公共示例 access key id），按 `report --confirm` 流程开了 issue。仓库 maintainer 关闭了 issue 并指出该字符串住在他们项目内部的 `KNOWN_EXAMPLE_KEYS` allowlist 里，是文档化的示例，无需轮换。这是一次对方礼貌、我方明显业余的事故。

## 时间线

- **披露**：scanner 在 `aws-access-key` 规则下命中目标仓库的源文件（具体路径推测在 `src/patterns.ts` 周边），将 finding 写进 `findings.json`，随后在某次 `report --confirm` 调用时被开成 GitHub issue
- **关闭**：maintainer 在 issue 下评论说该字符串是已知 example key、住在 allowlist 里，下游产出物（`dist/` 打包文件）里被另一个第三方扫描器（HMA）也命中、tracked in #52
- **结果**：issue 以 `closed as not planned` 关闭，maintainer 同时表扬了"通知 + 不验证 + 留出修复路径"的披露姿势是对的

## 根因

事故前的 `src/scan.rs::match_blob` 在正则命中后，**只**做两件事：
1. `min_len` 长度检查（`src/scan.rs:107-109`）
2. per-blob `(rule_id, sha256_prefix)` 去重（`src/scan.rs:113-117`）

任何长度合规、未在同 blob 内重复的 regex 命中都会成为 `Finding`，进入 `findings.json`，在下一步 `report --confirm` 时被开成 GitHub issue。**没有任何"内容白名单"层**——即使是 AWS 官方文档反复使用的、社区共识的示例字符串，也照样进 pipeline。

`src/rules.rs:125-133` 的 AWS 规则正则 `(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}`，min_len 20，能干净命中 `AKIAIOSFODNN7EXAMPLE`。

## 修复

新增 `src/filters.rs`，定义 `KNOWN_EXAMPLE_KEYS: HashSet<String>`，覆盖：

- `AKIA` + `IOSFODNN7EXAMPLE`（AWS IAM docs）
- `AKIAI44` + `QH8DHBEXAMPLE`（AWS IAM docs，第二个示例 access key id）
- `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`（AWS docs 公共示例 secret access key；当前 AWS 规则不匹配它，但提前登记，未来加 secret-key 规则时不会再 reintroduce 同一个 false positive）

调用点在 `src/scan.rs::match_blob` 里 `min_len` 检查之后、redact 之前：

```rust
if filters::is_known_example_key(key) {
    continue;
}
```

短路设计意图：示例 key **不消耗** SHA-256、不进 dedup HashSet、不进 `findings.json`。

源文件本身用 `format!` 拼接所有 example key 字符串，避免本仓库自身被其它扫描器（包括我们自己）当成泄漏命中——和 `src/redact.rs::tests` 里的 `format!("AKIA{}", "IOSFODNN7EXAMPLE")` 是同一个防御惯例。

测试：
- `filters::tests::matches_aws_documented_examples` / `rejects_other_aws_shaped_strings` / `case_sensitive` / `empty_and_short_inputs`
- `scan::tests::match_blob_suppresses_known_example_keys`（端到端：构造 blob 含示例 key，断言 `findings.is_empty()`）

## 经验

1. **新增 vendor 规则时必查"该厂商有没有公开示例 key"**。AWS、OpenAI（曾用 `sk-...`）、Stripe（`sk_test_...`）等多家文档里都流通过示例字符串。今后给 `wiki/vendors/<id>.md` 加一个 mandatory 字段 `example_keys: [...]`，ingest 时直接同步进 `src/filters.rs`。
2. **不做启发式过滤**（比如 "key contains EXAMPLE 就跳过"）。real-world 已经见过攻击者在真凭据里塞 `EXAMPLE` 字符串以躲过粗糙过滤；精确字符串白名单既准又稳。
3. **披露姿势对了就不丢人**。我们这次的礼貌通知姿势被 maintainer 表扬，false positive 本身没烧到关系——但把这条作为 incident 沉淀下来，避免下次再犯。
4. **下游产物里的同一字符串还会被其它扫描器命中**（issue 评论里提到的 #52 + HMA）。我们这边修了源就够了；目标仓库怎么处理 `dist/` 是他们的事。

## 受影响文件

- 新建：`src/filters.rs`、`wiki/incidents/2026-04-aws-example-key-fp.md`
- 修改：`src/main.rs`（`mod filters;`）、`src/scan.rs`（import + 调用 + 回归测）

## See Also

- `src/rules.rs:125-133` —— AWS 规则定义
- `src/scan.rs:100-140` —— `match_blob` 修改后的 pipeline
- `src/redact.rs:39-79` —— 既有的 "用 format! 防御本仓库被扫"惯例的源头
