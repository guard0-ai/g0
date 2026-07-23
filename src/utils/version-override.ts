// A build-agnostic version holder. Compiled single-file binaries (Bun) cannot
// `require('../../package.json')` at runtime, so the binary entry sets the real
// version here BEFORE any other module loads. Node/dev never sets it and the
// version falls back to reading package.json (see utils/version.ts).
let _override: string | undefined;

export function setVersionOverride(v: string): void {
  if (v) _override = v;
}

export function getVersionOverride(): string | undefined {
  return _override;
}
