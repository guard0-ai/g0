import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

const G0_DIR = path.join(os.homedir(), '.g0');
const MACHINE_ID_PATH = path.join(G0_DIR, 'machine-id');

export function getMachineId(): string {
  // Return cached value if file exists
  try {
    const existing = fs.readFileSync(MACHINE_ID_PATH, 'utf-8').trim();
    if (existing) return existing;
  } catch {
    // File doesn't exist yet, generate new
  }

  const id = crypto.randomUUID();

  // Ensure ~/.g0 directory exists
  fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(MACHINE_ID_PATH, id + '\n', { mode: 0o600 });

  return id;
}

export function getMachineIdPath(): string {
  return MACHINE_ID_PATH;
}
