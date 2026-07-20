import crypto from 'crypto';

// Base32-ish alphabet with visually ambiguous characters (0/O, 1/I/L) removed,
// so backup codes are easy for a human to transcribe correctly by hand.
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// 16 random bytes is the Argon2id-recommended minimum salt length. This salt
// is NOT secret — it has to be handed to the browser so it can re-derive the
// same master key on a later recovery attempt.
export function generateRecoverySalt(): string {
  return crypto.randomBytes(16).toString('base64url');
}

// One human-friendly one-time backup code, e.g. "7K9P-QX3M-2VZT".
export function generateBackupCode(): string {
  const groups: string[] = [];
  for (let g = 0; g < 3; g++) {
    let group = '';
    for (let i = 0; i < 4; i++) {
      group += CODE_ALPHABET[crypto.randomInt(0, CODE_ALPHABET.length)];
    }
    groups.push(group);
  }
  return groups.join('-');
}

export function generateBackupCodeSet(count: number): string[] {
  return Array.from({ length: count }, () => generateBackupCode());
}

// Deterministic, non-random pseudo-salt for an email that isn't registered.
// /recovery/salt returns THIS instead of a 404 so the endpoint's response
// shape/timing is identical whether or not the account exists, preventing
// account enumeration via the recovery flow.
export function pseudoSaltForUnknownEmail(email: string, pepper: string): string {
  return crypto
    .createHmac('sha256', pepper)
    .update(email.toLowerCase())
    .digest('base64url')
    .slice(0, 22);
}