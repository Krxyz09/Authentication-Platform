import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

export interface RecoveryBackupCode {
  codeHash: string;
  used: boolean;
  usedAt?: Date;
}

export interface User {
  id: string;
  email: string;
  faceDescriptor: number[]; // Layer 1 - facial biometric embedding (e.g. 128-d face-api.js descriptor)
  pinHash: string;          // Layer 1 - fallback PIN, bcrypt-hashed, used only after 3 failed face attempts

  // Emergency Path (Argon2id Zero-Knowledge Layer) — all optional until the
  // user completes recovery setup. See recovery.service.ts for how these are
  // populated; the server never sees the passphrase or master key itself.
  recoverySalt?: string;
  recoveryVerifierHash?: string;
  recoveryBackupCodes?: RecoveryBackupCode[];

  createdAt: Date;
}

export interface DeviceKey {
  id: string;
  userId: string;
  deviceName: string;
  credentialID: string;                          // Base64Url credential ID, unique per authenticator
  credentialPublicKey: Buffer;                    // Raw COSE public key bytes (ECDSA P-256 / alg -7)
  counter: number;                                // Anti-cloning replay counter signature tracking
  transports?: AuthenticatorTransportFuture[];    // e.g. ['internal'] for platform authenticators
  isVerified: boolean;                            // If false, it's trapped until cross-device approval passes
  createdAt: Date;
}

export interface JWTPayload {
  userId: string;
  email: string;
  layer1Cleared: boolean;
  layer2Cleared: boolean;
  // Set when this partial token was issued by the Emergency Path (Argon2id
  // recovery) rather than face/PIN. /register-verify uses this to grant a full
  // session immediately once the forced passkey re-enrollment succeeds.
  viaRecovery?: boolean;
}