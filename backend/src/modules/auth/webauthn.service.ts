import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { UserRepository } from '../user/user.repository.js';

const RP_NAME = process.env.RP_NAME || 'Tally Auth';
const RP_ID = process.env.RPID || 'localhost';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || 'http://localhost:5173';

export class WebAuthnService {
  private userRepo = new UserRepository();

  // Per-user challenge caches for the registration and authentication ceremonies.
  // Kept separate because a user could in theory be mid-registration on one
  // device while mid-login on another.
  private regChallengeCache = new Map<string, string>();
  private authChallengeCache = new Map<string, string>();

  // --- /api/auth/register-options ---
  async generateRegistrationOptionsForUser(userId: string, email: string) {
    const existingDevices = await this.userRepo.findDevicesByUserId(userId);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: email,
      userDisplayName: email,
      userID: new TextEncoder().encode(userId),
      attestationType: 'none',

      // Cryptographic Foundation: restrict to ECDSA P-256 (COSE alg identifier -7 / ES256).
      // No fallback algorithms are offered, so a non-P-256 authenticator cannot enroll.
      supportedAlgorithmIDs: [-7],

      // Don't let a device re-register a credential it already holds.
      excludeCredentials: existingDevices.map(d => ({
        id: d.credentialID,
        transports: d.transports as AuthenticatorTransportFuture[] | undefined
      })),

      authenticatorSelection: {
        // Discoverable, cloud-synced passkeys (not just device-local, non-syncable keys).
        residentKey: 'required',
        requireResidentKey: true, // legacy mirror of residentKey for older client libraries
        // Mandates the local biometric/PIN gate (FaceID/TouchID/Windows Hello/system PIN)
        // on the authenticator itself before it will sign anything.
        userVerification: 'required',
        // Restricts enrollment to platform authenticators (secure enclave / TPM-bound),
        // ruling out roaming/cross-platform security keys.
        authenticatorAttachment: 'platform'
      }
    });

    this.regChallengeCache.set(userId, options.challenge);
    return options;
  }

  // --- /api/auth/register-verify ---
  async verifyRegistration(userId: string, deviceName: string, response: any) {
    const expectedChallenge = this.regChallengeCache.get(userId);
    if (!expectedChallenge) throw new Error('Registration handshake challenge has expired.');

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      // Belt-and-suspenders: re-assert UV is required even though the options
      // already requested it, in case a non-conforming client ignored that hint.
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Registration signature verification failed.');
    }

    this.regChallengeCache.delete(userId);

    const { credential } = verification.registrationInfo;

    // Primary Principle: only credentialID + public key (+ counter/transports)
    // ever get persisted. No biometric template or raw image reaches this code
    // at all — the browser/authenticator never sends one for WebAuthn.
    const activeCluster = await this.userRepo.findDevicesByUserId(userId);
    const requiresCrossApproval = activeCluster.length > 0;

    const device = await this.userRepo.saveDeviceKey({
      userId,
      deviceName,
      credentialID: credential.id,
      credentialPublicKey: Buffer.from(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports,
      isVerified: !requiresCrossApproval // Auto-verify if first device; otherwise flag false
    });

    return requiresCrossApproval
      ? { status: 'PENDING_CROSS_APPROVAL', deviceId: device.id }
      : { status: 'PROVISIONED_ACTIVE', deviceId: device.id };
  }

  // --- /api/auth/login-options ---
  async generateLoginChallenge(userId: string) {
    const devices = await this.userRepo.findDevicesByUserId(userId);
    const verifiedDevices = devices.filter(d => d.isVerified);

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      // generateAuthenticationOptions() sources a fresh, cryptographically
      // random 32-byte challenge internally on every call.
      allowCredentials: verifiedDevices.map(d => ({
        id: d.credentialID,
        transports: d.transports as AuthenticatorTransportFuture[] | undefined
      })),
      userVerification: 'required'
    });

    this.authChallengeCache.set(userId, options.challenge);
    return options;
  }

  // --- /api/auth/login-verify ---
  async verifyLogin(userId: string, assertion: any): Promise<{ success: boolean }> {
    const expectedChallenge = this.authChallengeCache.get(userId);
    if (!expectedChallenge) throw new Error('Login handshake challenge has expired.');

    const device = await this.userRepo.findDeviceByCredentialID(assertion.id);
    if (!device) throw new Error('Cryptographic signature device binding unknown.');
    if (!device.isVerified) throw new Error('Device pending cross-confirmation authorization.');
    if (device.userId !== userId) throw new Error('Credential does not belong to this account.');

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      // Enforces the User Presence (UP) bit implicitly (always required by the
      // spec) and the User Verification (UV) bit explicitly here — both must be
      // 1 inside authenticatorData or verification fails.
      requireUserVerification: true,
      credential: {
        id: device.credentialID,
        // WebAuthnCredential expects Uint8Array<ArrayBuffer> specifically.
        // Buffer is a Uint8Array<ArrayBufferLike>, which also admits
        // SharedArrayBuffer — so TS won't accept it directly here.
        publicKey: new Uint8Array(device.credentialPublicKey),
        counter: device.counter,
        transports: device.transports as AuthenticatorTransportFuture[] | undefined
      }
    });

    if (!verification.verified) {
      return { success: false };
    }

    // Anti-Replay / Clone Mitigation: the library already rejects a non-increasing
    // counter internally (comparing against the counter we passed in above), but
    // we re-check explicitly here as a defense-in-depth guard before persisting.
    const { newCounter } = verification.authenticationInfo;
    if (newCounter !== 0 && newCounter <= device.counter) {
      throw new Error('Replay or cloned authenticator suspected: signature counter did not advance.');
    }

    this.authChallengeCache.delete(userId);
    await this.userRepo.updateDeviceCounter(device.id, newCounter);
    return { success: true };
  }
}