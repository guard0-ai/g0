# Phase 0 logistics — start day 1, parallel to the code tasks

These items block Phases 1–4 but are **not implementable by a coding agent** — they are
procurement and customer-facing actions. Track them explicitly (spec §11 "day-1 critical path").

## Code-signing / notarization (the true long-pole — spec §4, §12)
- [ ] Procure an **EV/OV Authenticode code-signing certificate** (Windows MSI + exe).
- [ ] Enroll in the **Apple Developer Program**; obtain a **Developer ID Installer**
      cert (PKG) and a **Developer ID Application** cert (binary).
- [ ] Stand up a **notarization** pipeline (`notarytool --wait` + `stapler staple`).

## Customer confirmation (gates the transport/enactment design — spec §15)
- [ ] Confirm the customer runs **ManageEngine Endpoint Central** (agent-based), NOT
      **Mobile Device Manager Plus** (no custom-script engine). If MDM Plus only,
      escalate — transport/enactment options shrink drastically.
- [ ] Confirm the **Windows/macOS split** and get **one Windows + one macOS pilot machine**.
- [ ] Identify the fleet **EDR/AV** (CrowdStrike / SentinelOne / Defender / …), the
      **allowlist owner**, and the **turnaround time** for allowlisting the resident daemon.
      (Gates whether daemon-first is viable at pilot, or we start scheduled-only.)
- [ ] Confirm where the **customer-hosted collector** can run (a box they control), or
      whether they prefer the Velociraptor path or ManageEngine script-output-only for the POC.

## Packaging toolchain (updated by the Phase-0 SEA finding)
- [ ] Node SEA is ruled out (ESM + top-level await + `import.meta.url`). Confirm the
      **Bun `--compile`** (or Deno `compile`) toolchain is acceptable in the release pipeline,
      or decide on the "embedded-node-runtime installer" alternative.
