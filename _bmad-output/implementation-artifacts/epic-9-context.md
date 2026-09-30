# Epic 9 Context: The whole-codebase meaty review — review prep and the human read

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-30: epic in backlog, no story files created yet — story keys append to the tracker as files appear. -->

## Goal

The owner performs ONE meaty human read of the WHOLE codebase — code and tests, every epic's output including Epic 8's — prepared by a review-prep package (change inventory, hot-spot map, risk annotations, recommended reading order) so the read is systematic instead of archaeological. Findings land in a triage ledger and bounce to their owning area (the honest-exception pattern: the review never patches what it reviews); fixes are taken in a follow-up round inside this epic. The read partially serves the trust-model success measure — the trust model survives a security-architect review (credential-free invariant holds, fail-closed default verified, accepted risks documented) — and precedes the performance epic, so performance proofs are built on reviewed ground.

## Stories

- No stories created yet (epic is in backlog; story keys append to the tracker as story files are created).
- Expected slicing (owner direction, 2026-09-19): review-prep package story → the owner's human read → findings-triage (+ fix round) story.

## Requirements & Constraints

- **The read covers everything:** code and tests from every epic, Epic 8's output included. One systematic whole-codebase pass — per-story reviews already exist; none has covered the corpus as a whole.
- **Review-prep package precedes the read:** change inventory, hot-spot map, risk annotations, recommended reading order. Success bar: the package exists, the read is completed, and every finding is triaged — fixed / ledgered / declined-with-reason.
- **Honest-exception discipline:** the review never patches what it reviews. Findings bounce to their owning area; fixes happen in a deliberate follow-up round inside this epic, sized by the findings and bounded by the triage.
- **Trust-model read hardening (partial serve of the security-architect-review measure):** verify the credential-free invariant holds, the fail-closed default is real in code, and accepted risks stay documented — the accepted-risk register is the explicit probe surface for this read.
- **Test-strategy review:** mock/conformance SMSC, TLS/OIDC test vectors, and codec fuzzing of both parsed surfaces (bind-family parser AND framing decoder — the more-exposed surface).
- **Security-posture read:** parser robustness (only bind/unbind inspected, everything else opaque relay; malformed/oversized/truncated PDUs rejected without crashing; backpressure against memory exhaustion) and no rolled crypto (mature libraries mandatory for crypto/TLS/OIDC; the from-scratch scope is the SMPP layer only).

## Technical Decisions

- **Process epic:** no functional requirements and no new architecture decisions — the review reads all existing ones; the test/conformance-toolchain decisions are the reference frame for the test-review half.
- **No main-source ownership:** the epic produces a review-prep artifact plus a findings/triage ledger; fix rounds touch owning packages only.
- **Positioning is deliberate:** execution priority is E6 → E8 → E9 → E7 — correctness proof before performance proof. The performance epic re-pins its baseline and starts only after this epic closes.

## Cross-Story Dependencies

- **Depends on Epic 8 (done):** the read explicitly reviews Epic 8's output (observability close-out, sandbox Prometheus, CI + Docker Hub publish) as part of its corpus.
- **Epic 7 waits on this epic:** performance proofs are built on reviewed ground; Epic 7 leaves the CI pipeline untouched except via explicit, task-required edits.
- **Findings fan out to owning areas** across all earlier epics (codec, proxy packages, sandbox, docs, CI) — the fix round executes here but edits owning packages only.
