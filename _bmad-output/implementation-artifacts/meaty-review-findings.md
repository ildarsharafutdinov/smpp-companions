# Epic 9 Findings & Triage Ledger

Created 2026-09-30 at Story 9.1 start (runbook human walkthrough). This is the **single
findings home for ALL Epic 9 stories**: every observation from the meaty review lands here
as a row, and every row carries an explicit verdict before its story closes. Deferrals that
need a future home outside the current story are mirrored in `deferred-work.md`.

## Verdict vocabulary

- **fixed** — corrected inside the story that found it; evidence cites the fixing commit or diff.
- **deferred** — real, but owned by a later story/epic; mirrored in `deferred-work.md`.
- **declined** — not a defect or not worth changing; reason required.
- **research** — needs more investigation before any verdict.

## Findings

| # | Date | Story | Surface | Observation | Verdict | Evidence |
|---|------|-------|---------|-------------|---------|----------|

<!-- Row shape: # = F1, F2, …; Date = YYYY-MM-DD; Story = 9.1…; Surface = file:line,
     runbook §step, log line, or metric series; Observation = what was seen vs what the
     docs promised; Verdict = fixed | deferred | declined | research; Evidence = commit,
     diff hunk, log excerpt, or scrape output backing the row. Long observations go in a
     numbered note below the table, with the row citing "note N". -->
