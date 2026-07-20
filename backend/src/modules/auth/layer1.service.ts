import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { UserRepository } from '../user/user.repository.js';
import { JWTPayload, User } from '../../types/index.js';
import { euclideanDistance, FACE_MATCH_THRESHOLD } from './face.utils.js';

const MAX_FACE_ATTEMPTS = 3;
const MAX_PIN_ATTEMPTS = 3;

interface AttemptRecord {
  count: number;
  lockedForPin: boolean;
}

export class Layer1Service {
  private userRepo = new UserRepository();
  private JWT_SECRET = process.env.JWT_SECRET || 'tally-secret-key-signature';

  // Tracks failed face-match attempts per in-progress login (keyed by email).
  private faceAttempts = new Map<string, AttemptRecord>();

  // Tracks failed PIN attempts per in-progress login, once the PIN fallback has
  // been unlocked by 3 failed face attempts. Separate from faceAttempts.count
  // because these are two independent 3-strike budgets on the same login attempt.
  private pinAttempts = new Map<string, number>();

  async signup(email: string, faceDescriptor: number[], pin: string, pinConfirm: string): Promise<User> {
    const existing = await this.userRepo.findByEmail(email);
    if (existing) throw new Error('An account already exists for this email.');

    if (!Array.isArray(faceDescriptor) || faceDescriptor.length === 0) {
      throw new Error('A valid facial biometric enrollment is required.');
    }
    if (!/^\d{4,6}$/.test(pin)) {
      throw new Error('PIN must be 4 to 6 digits.');
    }
    // PIN is captured twice on signup and must match before it is ever hashed —
    // this is the only chance to catch a typo, since only the hash is stored.
    if (pin !== pinConfirm) {
      throw new Error('PIN and PIN confirmation do not match.');
    }

    const pinHash = await bcrypt.hash(pin, 10);
    return this.userRepo.createUser(email, faceDescriptor, pinHash);
  }

  private issuePartialToken(user: User): string {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      layer1Cleared: true,
      layer2Cleared: false
    };
    return jwt.sign(payload, this.JWT_SECRET, { expiresIn: '5m' });
  }

  // Wipes both attempt budgets for this email, ending the current login attempt.
  // Called on success (fresh start next time) and on a hard PIN lockout (force restart).
  private resetLoginState(email: string): void {
    this.faceAttempts.delete(email);
    this.pinAttempts.delete(email);
  }

  async verifyFace(
    email: string,
    faceDescriptor: number[]
  ): Promise<{ success: boolean; partialToken?: string; requiresPin?: boolean; attemptsRemaining?: number }> {
    const user = await this.userRepo.findByEmail(email);
    if (!user) throw new Error('Authentication parameters invalid.');

    const record = this.faceAttempts.get(email) ?? { count: 0, lockedForPin: false };

    // Already burned through 3 attempts this login attempt — don't let the client
    // keep hammering the face endpoint, force it over to PIN.
    if (record.lockedForPin) {
      return { success: false, requiresPin: true, attemptsRemaining: 0 };
    }

    if (!Array.isArray(faceDescriptor) || faceDescriptor.length !== user.faceDescriptor.length) {
      throw new Error('Malformed facial biometric sample.');
    }

    const distance = euclideanDistance(faceDescriptor, user.faceDescriptor);

    if (distance <= FACE_MATCH_THRESHOLD) {
      this.resetLoginState(email);
      return { success: true, partialToken: this.issuePartialToken(user) };
    }

    record.count += 1;
    if (record.count >= MAX_FACE_ATTEMPTS) {
      record.lockedForPin = true;
      this.faceAttempts.set(email, record);
      return { success: false, requiresPin: true, attemptsRemaining: 0 };
    }

    this.faceAttempts.set(email, record);
    return { success: false, requiresPin: false, attemptsRemaining: MAX_FACE_ATTEMPTS - record.count };
  }

  async verifyPin(
    email: string,
    pin: string
  ): Promise<{ success: boolean; partialToken?: string; redirectToLogin?: boolean; attemptsRemaining?: number; message?: string }> {
    const user = await this.userRepo.findByEmail(email);
    if (!user) throw new Error('Authentication parameters invalid.');

    const record = this.faceAttempts.get(email);
    if (!record || !record.lockedForPin) {
      // Server-side enforcement: PIN fallback only opens up after 3 failed face
      // attempts on THIS login, so a client can't just skip straight to PIN.
      throw new Error('PIN fallback is not available yet — face verification must fail 3 times first.');
    }

    const pinFailCount = this.pinAttempts.get(email) ?? 0;

    const isMatch = await bcrypt.compare(pin, user.pinHash);

    if (!isMatch) {
      const newCount = pinFailCount + 1;

      // 3rd PIN failure: the entire login attempt is invalidated. Both the face
      // and PIN budgets are wiped so the client must restart from the main
      // login page (face verification) rather than keep retrying PIN.
      if (newCount >= MAX_PIN_ATTEMPTS) {
        this.resetLoginState(email);
        return {
          success: false,
          redirectToLogin: true,
          attemptsRemaining: 0,
          message: 'Too many failed PIN attempts. Please restart login.'
        };
      }

      this.pinAttempts.set(email, newCount);
      return {
        success: false,
        redirectToLogin: false,
        attemptsRemaining: MAX_PIN_ATTEMPTS - newCount
      };
    }

    this.resetLoginState(email);
    return { success: true, partialToken: this.issuePartialToken(user) };
  }
}