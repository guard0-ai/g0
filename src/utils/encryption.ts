import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const ALGORITHM = 'aes-256-gcm';
const MAGIC = Buffer.from('G0ENC1'); // 6-byte version header
const KEY_LENGTH = 32; // AES-256
const IV_LENGTH = 12; // GCM standard
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 100_000;
const SALT = Buffer.from('g0-encryption-salt-v1');

/**
 * Derive encryption key from machine identity.
 * Uses machine-id file if present, falls back to hostname+username.
 */
function deriveKey(): Buffer {
  let seed: string;

  const machineIdPath = path.join(os.homedir(), '.g0', 'machine-id');
  try {
    seed = fs.readFileSync(machineIdPath, 'utf-8').trim();
  } catch {
    seed = `${os.hostname()}:${os.userInfo().username}`;
  }

  return crypto.pbkdf2Sync(seed, SALT, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

/**
 * Encrypt plaintext string to a Buffer with magic header.
 * Format: [MAGIC 6B][IV 12B][AUTH_TAG 16B][CIPHERTEXT ...]
 */
export function encrypt(plaintext: string): Buffer {
  const key = deriveKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, iv, authTag, encrypted]);
}

/**
 * Decrypt data buffer back to string.
 * Backwards compatible: if magic header is missing, treats data as plaintext UTF-8.
 */
export function decrypt(data: Buffer): string {
  // Backwards compatibility: if no magic header, treat as plaintext
  if (!data.subarray(0, MAGIC.length).equals(MAGIC)) {
    return data.toString('utf-8');
  }

  const key = deriveKey();
  let offset = MAGIC.length;

  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;

  const authTag = data.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;

  const ciphertext = data.subarray(offset);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf-8');
}

/**
 * Read and decrypt a JSON file. Falls back to plaintext for unencrypted files.
 */
export function readEncryptedJson<T>(filePath: string): T | null {
  try {
    const data = fs.readFileSync(filePath);
    const json = decrypt(data);
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

/**
 * Encrypt and write a JSON value to file.
 */
export function writeEncryptedJson(filePath: string, value: unknown): void {
  const json = JSON.stringify(value, null, 2);
  const encrypted = encrypt(json);
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, encrypted, { mode: 0o600 });
}
