import mongoose, { Schema, type Document } from 'mongoose';
import { User, DeviceKey } from '../types/index.js';

export interface IUserDocument extends User, Document {}
export interface IDeviceDocument extends DeviceKey, Document {}

const recoveryBackupCodeSchema = new Schema(
  {
    codeHash: { type: String, required: true },
    used: { type: Boolean, default: false },
    usedAt: { type: Date }  
  },
  { _id: false }
);

const userSchema = new Schema<IUserDocument>({
  id: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  faceDescriptor: { type: [Number], required: true },
  pinHash: { type: String, required: true },

  // --- Emergency Path (Argon2id Zero-Knowledge Layer) ---
  // recoverySalt is not secret; it's handed to the browser so it can re-derive
  // the same master key on a later recovery attempt. recoveryVerifierHash is a
  // bcrypt hash of the browser-derived proof (never the passphrase or master
  // key itself). recoveryBackupCodes are single-use codes consumed one at a
  // time alongside the proof.
  recoverySalt: { type: String },
  recoveryVerifierHash: { type: String },
  recoveryBackupCodes: { type: [recoveryBackupCodeSchema], default: [] },

  createdAt: { type: Date, default: Date.now }
});

const deviceKeySchema = new Schema<IDeviceDocument>({
  id: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  deviceName: { type: String, required: true },
  credentialID: { type: String, required: true, unique: true, index: true },
  // Stored as a raw Buffer (COSE public key bytes), never as a derived/encoded string,
  // so verifyAuthenticationResponse() can do the curve-coordinate math directly against it.
  credentialPublicKey: { type: Buffer, required: true },
  counter: { type: Number, default: 0 },
  transports: { type: [String], default: [] },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

export const UserModel = mongoose.models.User || mongoose.model<IUserDocument>('User', userSchema);
export const DeviceKeyModel = mongoose.models.DeviceKey || mongoose.model<IDeviceDocument>('DeviceKey', deviceKeySchema);