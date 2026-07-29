# SMPP 3.4 Golden-Vector Corpus

This directory holds the golden-vector corpus for the codec (**CODEC-030**, AC5) — the codec's *third
oracle*: hand-authored-from-the-spec wire bytes that the parser/encoder are later checked against
(jSMPP field-by-field cross-oracle in T5/CODEC-031; the codec's own round-trip in CODEC-032).

**Status (Story 1.2 / T4):** populated — 6 positive bind-family vectors + 5 negative vectors. The
integrity of every vector is enforced by `GoldenVectorCorpusTest` (provenance header, parseable
lowercase `raw-hex`, and — for positive vectors — length-self-consistency + AD-30 bounds + a
bind-family `command_id`). The corpus is authored **independently of the codec**: no vector is ever
produced by invoking `SmppCodec` or `SmppBindEncoder` (R14/R33).

## File format — one-line provenance header

Every vector is a single-line text file (extension `.bin` or `.smpp`). Its first line is the
provenance header, of the form:

```
# provenance: <spec ref or SMPP 3.4 §section + field notes> ; raw-hex: <lowercase hex of the wire bytes>
```

A **negative** vector adds its expected reject outcome:

```
# provenance: <ref> ; raw-hex: <lowercase hex> ; reject: <CODEC-id reason>
```

* `provenance` — a stable citation of where the bytes came from (e.g.
  `SMPP 3.4 §4.1.4.1 BIND_TRANSCEIVER request, all fields`).
* `raw-hex` — the lowercase hexadecimal of the **exact** wire bytes (the whole PDU). This IS the
  vector — a drift in encoding is detectable by diff alone, and the loader decodes it via
  `java.util.HexFormat` (no binary/text duality, no header-vs-body drift).
* `reject` *(negative vectors only)* — the expected reject outcome, tagged with the CODEC scenario
  id it exercises (e.g. `CODEC-005 length<16`). Negative vectors are NOT length-self-consistent by
  design; their `raw-hex` is still validated as parseable lowercase hex.

The loader (`GoldenVectorCorpusTest.listVectors`) enumerates every `.bin`/`.smpp` regular file in
this directory and enforces the header on each.

## Corpus contents

**Positive** (length-self-consistent bind-family PDUs):

| File | PDU |
|---|---|
| `bind_transceiver_request_all_fields.smpp` | `bind_transceiver` request, every body field populated |
| `bind_transmitter_request_all_empty.smpp` | `bind_transmitter` request, all C-octet fields empty (CODEC-020 edge) |
| `bind_receiver_request_all_fields.smpp` | `bind_receiver` request, all fields + `address_range=123` |
| `bind_receiver_resp_rok.smpp` | `bind_receiver_resp`, `ESME_ROK`, `system_id` only (AD-25 `isOk=true`) |
| `bind_transceiver_resp_rok_tlv.smpp` | `bind_transceiver_resp`, `ESME_ROK`, `system_id` + `sc_interface_version` TLV (tail opaque, AD-3) |
| `bind_receiver_resp_rinvpaswd.smpp` | `bind_receiver_resp`, `ESME_RINVPASWD` non-ROK denial, `system_id` present (decodes clean, `isOk=false`, AD-25/CODEC-019) |

**Negative** (each tagged with its expected reject outcome):

| File | Malformation | Reject |
|---|---|---|
| `negative_length_below_16.smpp` | `command_length = 15 < MIN(16)` | `CODEC-005 length<16` |
| `negative_length_above_65536.smpp` | `command_length = 65537 > MAX(65536)` (off-by-one) | `CODEC-008 length>65536` |
| `negative_truncated_header.smpp` | only 12 octets (< 16, incomplete header) | `CODEC-009 header-incomplete` |
| `negative_unterminated_string.smpp` | valid-length body, no NUL terminator | `CODEC-021 unterminated-c-octet` |
| `negative_body_shorter_than_fields.smpp` | body holds only `system_id`, missing the rest | `CODEC-022 body-shorter-than-fields` |

## Adding a vector

1. Hand-author the wire bytes from `docs/SMPP_v3_4_Issue1_2.pdf` (do **not** generate them via the
   codec). Compute `command_length` = 16 + body octets for a positive PDU.
2. Drop a `.bin`/`.smpp` file here whose single line is the provenance header above, with the
   lowercase hex of those bytes in `raw-hex:`. Add ` ; reject: CODEC-… ` only for a negative vector.
3. `GoldenVectorCorpusTest` enforces the rest automatically (header shape, parseable hex, and — for
   positive vectors — `command_length` == byte count, AD-30 bounds, bind-family `command_id`).
