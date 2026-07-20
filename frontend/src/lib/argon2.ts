import { argon2id } from 'hash-wasm';

export interface Argon2Params {
  algorithm: 'argon2id';
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
}

/**
 * Derives the 32-byte master key from the user's passphrase + the server-
 * issued salt. Argon2id runs entirely here, in the browser (via WASM) — the
 * passphrase and the resulting master key never leave this function scope
 * as anything other than the further-derived proof below.
 */
export async function deriveMasterKey(
  passphrase: string,
  saltB64Url: string,
  params: Argon2Params
): Promise<Uint8Array> {
  const salt = base64UrlToBytes(saltB64Url);
  const hex = await argon2id({
    password: passphrase,
    salt,
    memorySize: params.memoryCost,
    iterations: params.timeCost,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
    outputType: 'hex'
  });
  return hexToBytes(hex);
}

/**
 * Derives a one-way "proof" from the master key via SHA-256 with a fixed
 * context string. This — never the master key or the passphrase — is what
 * gets sent to the server. Keep this context distinct from any local
 * encryption key you might later derive from the same master key, so the two
 * remain cryptographically unrelated.
 */
export async function deriveRecoveryProof(masterKey: Uint8Array): Promise<string> {
  const context = new TextEncoder().encode('tally-recovery-auth-proof-v1');
  const combined = new Uint8Array(masterKey.length + context.length);
  combined.set(masterKey, 0);
  combined.set(context, masterKey.length);
  const digest = await crypto.subtle.digest('SHA-256', combined);
  return bytesToHex(new Uint8Array(digest));
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}