# Attestation & Evidence

Scanners find issues; auditors need **evidence**. `g0 attest` turns a scan into a
portable, signed attestation pack: the score, the finding severity profile, and a
per-standard control-coverage matrix — bound by a content hash and an optional
ed25519 signature.

```bash
g0 attest .                                   # print an attestation pack (JSON)
g0 attest . -o attestation.json               # write to a file
g0 attest . --sign-key g0-signing.key -o attestation.json   # signed
g0 attest . --no-evidence                     # skip the durable evidence record
```

Use `g0 inventory --gen-key g0-signing` once to mint an ed25519 keypair.

## What a pack contains

```jsonc
{
  "schema": "g0-attestation/1",
  "project": "my-agent",
  "generatedAt": "2026-07-08T...",
  "tool": "g0@2.0.0",
  "scan": {
    "score": 55, "grade": "F",
    "capReason": "3 exploitable critical findings",
    "totalFindings": 41,
    "bySeverity": { "critical": 3, "high": 12, "medium": 20, "low": 6, "info": 0 }
  },
  "standards": [
    { "key": "owaspAgentic", "name": "OWASP Agentic Security",
      "findingCount": 16,
      "controls": [ { "control": "ASI01", "findingCount": 4, "severities": {"critical":1,"high":3} } ] },
    { "key": "euAiAct", "name": "EU AI Act", "findingCount": 1, "controls": [...] }
  ],
  "evidence": { "id": "…", "sha256": "…" },
  "contentHash": "…",       // sha256 over the pack (excludes generatedAt / signature)
  "signature": { "algorithm": "ed25519", "bomHash": "<contentHash>", "signature": "…", "publicKey": "…" }
}
```

The standards matrix maps findings to the controls of all 10 tracked frameworks
(OWASP Agentic, OWASP Agentic Top 10, OWASP LLM Top 10, OWASP AIVSS, NIST AI RMF,
ISO 42001, ISO 23894, EU AI Act, AIUC-1, MITRE ATLAS). Only standards with at
least one implicated finding are included.

## Integrity & durability

- **contentHash** is a SHA-256 over the pack that excludes `generatedAt` and the
  signature, so the same scan result always hashes identically.
- **signature** (when `--sign-key` is passed) is a detached ed25519 signature
  over `contentHash`, with the SPKI public key embedded. Any consumer can verify
  it independently, or via the `verifyBomSignature` SDK export.
- **evidence** links a durable record persisted under `~/.g0/evidence`
  (month-partitioned, SHA-256 hashed, standards-tagged). Skip with
  `--no-evidence`.

## Programmatic use

```typescript
import { buildAttestationPack, buildStandardsCoverage } from '@guard0/g0';
```

For org-wide compliance reports, audit trails, and attestation history across
your fleet, see the [Guard0 Platform](https://guard0.ai/early-access).
