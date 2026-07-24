# SMPP 3.4 Golden-Vector Corpus

This directory holds the golden-vector corpus for the codec (CODEC-030).

**Status (Story 1.1):** scaffold only — the corpus is intentionally EMPTY here. The non-empty +
provenance assertion (CODEC-030) is authored in Story 1.2 once the framer / bind parser produce
real wire bytes. Today this directory + its loader harness + the provenance-header convention below
are the only deliverables.

## Provenance-header convention

Every vector file MUST carry a provenance header as its first line, of the form:

```
# provenance: <spec ref or RFC/3.4 section> ; raw-hex: <lowercase hex of the encoded bytes>
```

* `provenance` — a stable citation of where the bytes came from (e.g. `SMPP 3.4 §4.1 BIND_RECEIVER`
  or a captured session fixture id).
* `raw-hex` — the lowercase hexadecimal of the exact bytes the vector decodes to / encodes from, so
  a drift in encoding is detectable by diff alone.

The loader harness (`GoldenVectorCorpusTest`) enforces this header on every vector present. While
the corpus is empty the harness passes trivially — that is the invariant lock, not a completion
claim.
