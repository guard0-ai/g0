/**
 * Detached signing for AI-BOM artifacts.
 *
 * Binds a BOM's content hash with an ed25519 signature so a consumer can verify
 * the BOM was produced by the holder of a given key and has not been altered.
 * Uses only node:crypto — no external dependencies, no network.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

export interface BomSignature {
  algorithm: 'ed25519';
  /** The value that was signed (the BOM content hash). */
  bomHash: string;
  /** Base64 detached signature over bomHash. */
  signature: string;
  /** PEM (SPKI) public key for verification. */
  publicKey: string;
  signedAt: string;
}

/** Generate a fresh ed25519 keypair as PEM strings. */
export function generateKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

/** Sign a BOM hash with an ed25519 private key (PEM). */
export function signBomHash(bomHash: string, privateKeyPem: string, signedAt: string): BomSignature {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const signature = crypto.sign(null, Buffer.from(bomHash, 'utf-8'), privateKey);
  return {
    algorithm: 'ed25519',
    bomHash,
    signature: signature.toString('base64'),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    signedAt,
  };
}

/** Verify a detached BOM signature. Returns true iff the signature is valid. */
export function verifyBomSignature(sig: BomSignature): boolean {
  try {
    const publicKey = crypto.createPublicKey(sig.publicKey);
    return crypto.verify(
      null,
      Buffer.from(sig.bomHash, 'utf-8'),
      publicKey,
      Buffer.from(sig.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

/** Load a private key PEM from disk (throws on missing/unreadable). */
export function loadPrivateKey(path: string): string {
  return fs.readFileSync(path, 'utf-8');
}
