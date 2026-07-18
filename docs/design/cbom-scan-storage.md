# CBOM scan storage — design & implementation plan

Status: **All phases (0–6) implemented & tested** (2026-07-13).

Verified: `cyclonedx-python-lib==11.11.0`; testssl (26 assets) and ssh-audit
(35 assets) fixtures both build schema-valid CycloneDX 1.6 CBOMs; **157 tests
pass in the built dev image** against real Postgres, including the real
testssl/nmap binary tests and a real testssl→CBOM end-to-end. ssh-audit was
validated against real OpenSSH_10.3 output (captured as a fixture). The mapper
was re-sourced from the official nmap/testssl data files.

## 1. Overview

Scans are stored in three layers, with a strict "**store facts, derive opinions**"
principle (verdicts drift as PQC/NIST guidance changes; raw facts never do):

```
Layer 1  RAW      raw testssl / ssh-audit JSON     facts, as-emitted, vendor-specific, reproducible
Layer 2  CBOM     CycloneDX 1.6 crypto inventory   facts, normalized, vendor-neutral   (built from L1)
Layer 3  OPINION  quantum-safe / weak / policy     judgment                            (derived from L2)
```

## 2. Confirmed decisions

- CBOM standard: **CycloneDX 1.6 cryptographic assets**, via the official
  **`cyclonedx-python-lib`** (models `CryptoProperties` / `AlgorithmProperties` / …).
- **Full inventory** CBOM (all 4 assetTypes), **1 CBOM per raw scan** (1:1).
- Opinion in a **separate, re-derivable store** (not embedded in the CBOM).
- Storage: raw + CBOM in **FK-linked tables**; opinion in its own table.
- CBOM built **every scan by default**; alt modes = raw-only + build-on-demand, or
  backfill only what's missing/stale (builder is versioned).
- Add **ssh-audit** as a scanner parallel to testssl; dispatch on
  `endpoint.application_protocol` (`ssh` → ssh-audit, else testssl), **not** `tls_mode`.
- SSH protocol asset links negotiated algorithms via `protocolProperties.cryptoRefArray`.
- Opinion captures **both** our PQC/policy verdict **and** vendor verdicts
  (testssl `rating`/`vulnerabilities`, ssh-audit `notes`/`cves`/`recommendations`).
- Certificate: **leaf cert + its public key first**; full chain deferred.
- `headerResponse` / `browserSimulations` / `vulnerabilities` are **excluded** from the
  CBOM (raw + opinion only).

## 3. Storage schema (3 tables)

No Alembic in the project — schema is `Base.metadata.create_all` via `tlssec init`.
New tables appear on next `init`; no prod data to migrate.

| Table | Columns |
|---|---|
| `scan` (raw; existing table, extended) | id, belong_to_endpoint_id→FK, **scanner** (`testssl`\|`ssh_audit`), **scanner_version**, result JSONB, start_time, time_taken |
| `cbom` (new) | id, **scan_id→FK (unique, 1:1)**, builder_version, document JSONB (CycloneDX 1.6), created_at |
| `opinion` (new) | id, **cbom_id→FK**, ruleset_version, verdict JSONB, created_at |

"Build only what's lacking" = `scan LEFT JOIN cbom WHERE cbom IS NULL OR builder_version < current`
(same pattern for `cbom → opinion`).

Open mechanic: keep raw table name `scan` (least churn, `import_scan` untouched) vs
rename to `raw_scan` (cleaner). Default: **keep `scan`, add columns**.

## 4. CBOM mapping (full inventory)

### TLS (testssl `--json-pretty`) → CycloneDX

| Asset | Source ids |
|---|---|
| `protocol` (type=tls, per version) | `protocols[]`; `serverPreferences.cipher-tls1_2_*` / `supportedciphers_*` → `cipherSuites[]` (name + hex id) |
| `algorithm` key-agree / kem | `fs.FS_ECDHE_curves`, `fs.DH_groups` (key-agree, `curve`); `fs.FS_KEMs` (kem, `nistQuantumSecurityLevel`) |
| `algorithm` block/stream-cipher | `fs.FS_ciphers` + suite names → `primitive`, `mode` |
| `algorithm` signature / hash | `fs.FS_TLS13_sig_algs`, `fs.FS_TLS12_sig_algs`, `serverDefaults.cert_signatureAlgorithm` |
| `certificate` (leaf) | `serverDefaults.cert_commonName`, `cert_subjectAltName`, `cert_caIssuers`, `cert_notBefore/notAfter`, `cert_signatureAlgorithm`→ref, `cert_fingerprintSHA256`, `cert_serialNumber` |
| `related-crypto-material` (public-key) | `serverDefaults.cert_keySize` (algo + size) |

### SSH (ssh-audit `--json`) → CycloneDX

| Asset | Source keys |
|---|---|
| `protocol` (type=ssh) | `banner.protocol`; negotiated algos via `protocolProperties.cryptoRefArray` |
| `algorithm` key-agree / kem | `kex[]` (dh/ecdh → key-agree; sntrup761x25519 / mlkem → kem + `nistQuantumSecurityLevel`) |
| `algorithm` signature | `key[]` host-key algs |
| `algorithm` block/stream-cipher | `enc[]` (mode from name) |
| `algorithm` mac | `mac[]` |
| `related-crypto-material` | `fingerprints` (digest); host key → public-key |

Verified CycloneDX vocab: `primitive ∈ {kem, key-agree, block-cipher, stream-cipher,
signature, hash, mac, kdf, ae, …}`, `mode ∈ {cbc, gcm, ctr, …}`, `nistQuantumSecurityLevel`;
`protocolProperties.type ∈ {tls, ssh, …}`;
`certificateProperties.{subjectName, issuerName, notValidBefore/After, signatureAlgorithmRef, subjectPublicKeyRef}`;
`relatedCryptoMaterialProperties.type ∈ {public-key, digest, shared-secret, …}`.

## 5. Opinion layer

- Ours (from CBOM facts): PQC safe/unsafe (existing `standard.tls` logic moves here and
  generalizes), weak protocol/cipher, cert expiry/trust.
- Vendor (from raw): testssl `rating.overall_grade` + `vulnerabilities[]`;
  ssh-audit per-algo `fail/warn/info` + `cves` + `recommendations`.

## 6. Module layout

- `core/cbom/` — `BUILDER_VERSION`, `build_from_testssl`, `build_from_sshaudit`, dispatch;
  uses `cyclonedx-python-lib`.
- `core/sshaudit/` — async wrapper mirroring `Testssl` (subprocess `--json`; in-process
  API is an option since ssh-audit is a Python dep).
- `core/opinion/` — `RULESET_VERSION`, `derive(cbom, raw)`.

## 7. Implementation phases

Vertical slice for testssl first (1–4), then ssh-audit breadth (5), then mapper cleanup (6).
Phase 6 is independent and can be pulled earlier as a quick win.

0. **[DONE] Deps** — added `cyclonedx-python-lib` (main) + `jsonschema` (dev, for CBOM
   schema-validation in tests). ssh-audit already present; testssl/nmap in image.
1. **[DONE] Storage model** — extended `ScanTable` (`scanner` enum default testssl,
   `scanner_version`); added `CbomTable` (1:1 FK to scan) + `OpinionTable` (FK to cbom,
   versioned history) + Pydantic `Cbom`/`Opinion` + relationships + re-exports; conftest
   deletes opinion→cbom→scan in FK order.
2. **[DONE] CBOM builder (testssl)** — `core/cbom` (`BUILDER_VERSION='0.1.0'`) +
   `core/cbom/testssl.py`; schema-validated against CycloneDX 1.6.
3. **[DONE] Opinion (testssl)** — `core/opinion` (`RULESET_VERSION='0.1.0'`): quantum /
   weakness / certificate from CBOM + captured testssl `rating`/`vulnerabilities`.
4. **[DONE] Orchestrate testssl slice** — `scan` builds raw→cbom→opinion by default;
   `--no-cbom` / `--no-opinion`; `cbom build` backfill (missing or stale builder/ruleset);
   `op.store_cbom_for_scan` / `backfill_cboms` / `backfill_opinions`.
5. **[DONE] ssh-audit breadth** — `core/sshaudit` wrapper; `core/cbom/sshaudit.py`
   (`build_from_sshaudit`, shared `core/cbom/_base.py`); opinion generalized to be
   scanner-agnostic (PQC via CBOM `nistQuantumSecurityLevel`) + ssh-audit vendor verdict;
   `scan` dispatches by `application_protocol`. nmap already surfaces SSH endpoints via its
   generic per-open-port extraction (port 22 → `application_protocol='ssh'`, `tls_mode=none`),
   so no nmap change was needed. Real OpenSSH_10.3 fixture + tests.
6. **[DONE] Mapper fix (#5)** — removed the implicit-TLS `smtps` from the STARTTLS map and
   added the real nmap XMPP names (`jabber`, `xmpp-client`), verified against
   `nmap-service-probes` + `nmap-services`; `tls_mode` detection refactored into
   `Nmap._detect_tls_mode` (both `-sV` `tunnel="ssl"` AND a port/service heuristic) with
   `-sV` now on by default in discovery; test asserts every mapped value ∈ testssl's
   documented `--starttls` set.

## 8. Mapper audit detail (#5)

- testssl values (right side): all valid per the official man page —
  `ftp, smtp, pop3, imap, xmpp, sieve, xmpp-server, telnet, ldap, irc, lmtp, nntp, postgres, mysql`.
- nmap keys (left side): `smtps→smtp` is wrong (smtps/imaps/pop3s/ftps/ldaps are *implicit*
  TLS, no `--starttls`); `xmpp` may be `jabber`; `postgres` is a dead key.
- Coupled bug: `tls_mode` uses `tunnel="ssl"` (only under `-sV`), but discovery defaults
  `detect_version=False` → implicit-TLS :443 misclassified `explicit`.
