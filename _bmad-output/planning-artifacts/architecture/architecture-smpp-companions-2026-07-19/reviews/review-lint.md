# Mechanical Lint Review — ARCHITECTURE-SPINE.md

- **Workspace:** `architecture-smpp-companions-2026-07-19`
- **Target:** `ARCHITECTURE-SPINE.md`
- **Linter:** `bmad-architecture/scripts/lint_spine.py`
- **Date:** 2026-07-19
- **Verdict:** PASS (0 findings)

## Lint command

```
uv run .claude/skills/bmad-architecture/scripts/lint_spine.py \
  --workspace .../architecture-smpp-companions-2026-07-19
```

## Raw linter output

```json
{
  "ok": true,
  "spine": "ARCHITECTURE-SPINE.md",
  "total_findings": 0,
  "by_severity": {},
  "findings": []
}
```

The linter checks four classes of mechanical defect (exit code is always 0; findings travel
in the JSON):

| Category | What it detects |
| --- | --- |
| `placeholder` | literal `TBD` / `TODO` / `FIXME` / `XXX`, "similar to AD-n" cross-refs, unfilled `{template-token}` (outside fences and in frontmatter) |
| `ad_id` | duplicate or non-monotonic (non-ascending) `AD-n` identifiers |
| `ad_fields` | an AD block missing any of `Binds` / `Prevents` / `Rule` |
| `version_pin` | a `## Stack` table row with a blank/placeholder version |

Fenced code blocks (mermaid + source tree) are blanked before scanning, so they neither trip
false positives nor hide real issues, and reported line numbers line up with the real file.

## Interpretation — manual corroboration of each check class

The linter returned clean. Each check class was corroborated against the file:

### 1. Placeholders — none
- No `TBD` / `TODO` / `FIXME` / `XXX` anywhere in the body or frontmatter.
- No dangling "similar to AD-n" cross-references.
- No unfilled `{template-token}` skeletons. (Fenced content — e.g. `src/main/java/io/companions/codec/…` — is correctly excluded; `…` is an ellipsis in a source-tree sketch, not a template token.)
- Frontmatter is fully populated (`name`, `paradigm`, `scope`, `created`, `updated`, `binds`, `sources`). Note: spine `status: draft` is the expected spine lifecycle state and is not a placeholder; the PRD's `status: final` is the product-contract state and is independent.

### 2. AD identifiers — all ascending, no duplicates
- 24 architectural decisions, `AD-1` through `AD-24`, monotonically ascending, no reuse, no gaps, no renumbers.
- Heading-level `[ADOPTED]` markers on AD-1, AD-3, AD-7, AD-9, AD-10, AD-11, AD-13, AD-14, AD-15, AD-18 are status annotations, not separate IDs, and do not affect ordering.

### 3. AD required fields — all present
Every AD block contains `**Binds:**`, `**Prevents:**`, and `**Rule:**`. No AD is missing any of the three required fields. (The linter keys on the lowercase substrings `binds`, `prevents`, `rule`; all 24 satisfy it.)

### 4. Stack version pins — all pinned
The `## Stack` table pins every entry:
- JDK — 25 LTS (pin build 25.0.x)
- Netty — 4.2.16.Final (via `netty-bom`)
- Spring Boot — 4.1.x (Spring Framework 7.0.8+)
- Micrometer — ships with Spring Boot 4
- Nimbus JOSE+JWT — 10.9.1 (≥10.0.2 for CVE-2025-53864)
- jSMPP — `org.jsmpp:jsmpp:3.0.2`
- GraalVM — for JDK 25 (Oracle 25.1.3 / CE 25.0.2), stretch only
- GC — generational ZGC (only ZGC mode in JDK 25)
- Runtime image — jlink ~45–66 MB
- Reference IdP — Keycloak 26.x
- Build/platform — Gradle multi-module · Linux x86/ARM · IPv4 · Apache-2.0

No row carries a blank or `{token}` version.

### 5. Mermaid — not covered by the linter; manually inspected
The linter does not parse mermaid (fences are blanked before scanning). The four mermaid
blocks were inspected for syntactic validity:

1. **Design Paradigm (lines 45–60)** — `flowchart TB`, two subgraphs, edge labels with `<br/>` and quoted strings. Valid.
2. **Module seam (lines 101–106)** — `graph BT`, two nodes, one `proxy --> codec` edge. Valid.
3. **Topology & per-leg TLS (lines 243–253)** — `graph LR`, four nodes, solid + dotted edges, multi-line quoted labels with `<br/>`. Valid.
4. **Deployment envelope (lines 259–273)** — `graph TB`, one subgraph, solid + dotted edges. Valid.

No broken pipes, no unterminated quotes, no orphan subgraph declarations.

## Findings

None. The spine is mechanically clean across all four linter categories, and the mermaid
diagrams the linter does not cover are syntactically valid on manual inspection.

## Notes for downstream reviewers (not lint findings)

These are out of scope for the mechanical pass and are flagged only so the rubric / semantic
walker inherits them — they are NOT lint findings and do not affect the PASS verdict:

- The spine `status` is `draft`. The lint pass does not police lifecycle status; the gate
  owner decides when to flip to `final`.
- Several ADs (AD-2, AD-12, AD-17, AD-19, AD-22, AD-24) intentionally push detail to package
  / config / test layers via the `## Deferred` section. This is the spine's lean-by-design
  contract, not a missing-field defect.
- "Cross-artifact items (reconcile with brief / PRD at finalize)" are explicitly deferred
  reconciliations, not placeholders — the lint pass correctly does not flag them.
