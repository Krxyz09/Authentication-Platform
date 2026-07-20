import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { UserRepository } from '../user/user.repository.js';
import { JWTPayload } from '../../types/index.js';
import {
  generateRecoverySalt,
  generateBackupCodeSet,
  pseudoSaltForUnknownEmail
} from './recovery.utils.js';

/**
 * The Emergency Path (Argon2id Zero-Knowledge Layer).
 *
 * Everything Argon2id runs CLIENT-SIDE, in the browser (next chat). This
 * service never receives, computes, or stores a passphrase or a master key —
 * only the already-derived, non-reversible "proof" the browser sends, which
 * gets bcrypt-hashed again before it ever touches the database. If the DB
 * leaks, an attacker still has to run Argon2id themselves against every
 * passphrase guess before they even get to attack the bcrypt layer.
 */

// OWASP-baseline Argon2id parameters (~19 MiB memory, t=2, p=1, 32-byte output).
// These are handed to the browser so both sides derive from the same recipe;
// tune for your target device's WASM performance when you build the frontend.
export const ARGON2ID_PARAMS = {
  algorithm: 'argon2id' as const,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32
};

const RECOVERY_BACKUP_CODE_COUNT = 8;
const MAX_RECOVERY_ATTEMPTS = 5;
const RECOVERY_LOCKOUT_MS = 15 * 60 * 1000;
const RECOVERY_PEPPER = process.env.RECOVERY_SALT_PEPPER || 'tally-recovery-pepper-change-me';
const JWT_SECRET = process.env.JWT_SECRET || 'tally-secret-key-signature';

// Fixed bcrypt hash with no known plaintext, used to burn the same CPU time as
// a real bcrypt.compare() when the account (or its recovery setup) doesn't
// exist, so failure timing can't be used to distinguish the two cases.
const DUMMY_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8G8k8G8k8G8k8G8k8G8k8G8k8G8k8G';

interface AttemptRecord {
  count: number;
  lockedUntil: number | null;
}

export class RecoveryService {
  private userRepo = new UserRepository();

  // Per-email lockout tracking for recovery attempts. Kept separate from
  // Layer1Service's face/PIN attempt maps — recovery is a distinct, higher-value
  // target since a successful attempt bypasses Layer 1 and Layer 2 entirely.
  private attempts = new Map<string, AttemptRecord>();

  // --- /api/auth/recovery/setup-init (requires Layer-1-cleared partial token) ---
  async initSetup(userId: string) {
    const salt = generateRecoverySalt();
    await this.userRepo.setRecoverySalt(userId, salt);
    return { salt, argon2Params: ARGON2ID_PARAMS };
  }

  // --- /api/auth/recovery/setup-complete ---
  // `proof` should be a value the browser derived FROM the Argon2id master key
  // via a second, one-way step (e.g. HKDF(masterKey, info="recovery-auth")) —
  // kept distinct from any local encryption key derived from the same master
  // key, so this proof reveals nothing usable even if intercepted.
  async completeSetup(userId: string, proof: string) {
    if (!proof || typeof proof !== 'string' || proof.length < 16) {
      throw new Error('Invalid recovery proof.');
    }

    const proofHash = await bcrypt.hash(proof, 10);
    const codes = generateBackupCodeSet(RECOVERY_BACKUP_CODE_COUNT);
    const codeHashes = await Promise.all(codes.map(c => bcrypt.hash(c, 10)));

    await this.userRepo.setRecoveryVerifier(userId, proofHash, codeHashes);

    // Plaintext codes are returned exactly once here — show these to the user
    // and never persist or log them. The server only ever keeps the hashes.
    return { success: true, backupCodes: codes };
  }

  // --- /api/auth/recovery/salt (public, pre-login) ---
  // Always returns a same-shaped response, registered email or not, so this
  // endpoint can't be used to enumerate accounts.
  async getSaltForEmail(email: string) {
    const user = await this.userRepo.findByEmail(email);
    if (user?.recoverySalt) {
      return { salt: user.recoverySalt, argon2Params: ARGON2ID_PARAMS };
    }
    return { salt: pseudoSaltForUnknownEmail(email, RECOVERY_PEPPER), argon2Params: ARGON2ID_PARAMS };
  }

  // --- /api/auth/recovery/status (requires Layer-1-cleared partial token) ---
  async getStatus(userId: string) {
    const user = await this.userRepo.findById(userId);
    if (!user) throw new Error('User not found.');
    return {
      configured: !!user.recoveryVerifierHash,
      remainingBackupCodes: user.recoveryBackupCodes?.filter(c => !c.used).length ?? 0
    };
  }

  private isLocked(email: string): boolean {
    const record = this.attempts.get(email);
    return !!record?.lockedUntil && record.lockedUntil > Date.now();
  }

  private registerFailure(email: string): void {
    const record = this.attempts.get(email) ?? { count: 0, lockedUntil: null };
    record.count += 1;
    if (record.count >= MAX_RECOVERY_ATTEMPTS) {
      record.lockedUntil = Date.now() + RECOVERY_LOCKOUT_MS;
      record.count = 0;
    }
    this.attempts.set(email, record);
  }

  private resetAttempts(email: string): void {
    this.attempts.delete(email);
  }

  // --- /api/auth/recovery/verify (public, pre-login) ---
  // Requires BOTH the Argon2id-derived proof AND one unused backup code. On
  // success: consumes that backup code, drops every enrolled passkey (Force
  // Passkey Re-enroll), and returns a partial token flagged `viaRecovery` so
  // /register-verify knows to grant a full session as soon as the replacement
  // passkey is registered, instead of requiring a separate login step.
  async verifyRecovery(
    email: string,
    proof: string,
    backupCode: string
  ): Promise<{ success: boolean; partialToken?: string; message?: string }> {
    const normalizedEmail = (email || '').toLowerCase();

    if (this.isLocked(normalizedEmail)) {
      return { success: false, message: 'Too many failed attempts. Try again later.' };
    }

    const user = await this.userRepo.findByEmail(normalizedEmail);

    if (!user || !user.recoveryVerifierHash || !user.recoveryBackupCodes?.length) {
      await bcrypt.compare(proof || '', DUMMY_HASH); // normalize timing
      this.registerFailure(normalizedEmail);
      return { success: false, message: 'Recovery verification failed.' };
    }

    const proofMatches = await bcrypt.compare(proof || '', user.recoveryVerifierHash);

    // Every unused code has to be checked — we don't store which one the user
    // is submitting, only hashes. Fine at RECOVERY_BACKUP_CODE_COUNT (8) codes.
    let matchedCodeHash: string | null = null;
    for (const entry of user.recoveryBackupCodes) {
      if (entry.used) continue;
      if (await bcrypt.compare(backupCode || '', entry.codeHash)) {
        matchedCodeHash = entry.codeHash;
        break;
      }
    }

    if (!proofMatches || !matchedCodeHash) {
      this.registerFailure(normalizedEmail);
      return { success: false, message: 'Recovery verification failed.' };
    }

    this.resetAttempts(normalizedEmail);
    await this.userRepo.consumeBackupCode(user.id, matchedCodeHash);
    await this.userRepo.dropAllDevicesForUser(user.id);

    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      layer1Cleared: true,
      layer2Cleared: false,
      viaRecovery: true
    };
    const partialToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '5m' });

    return { success: true, partialToken };
  }
}