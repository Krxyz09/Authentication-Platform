import { connectToDatabase } from '../../config/db.js';
import { UserModel, DeviceKeyModel } from '../../models/user.model.js';
import { User, DeviceKey } from '../../types/index.js';

export class UserRepository {
  private async ensureConnected(): Promise<void> {
    await connectToDatabase();
  }

  async createUser(email: string, faceDescriptor: number[], pinHash: string): Promise<User> {
    await this.ensureConnected();
    const newUser = await UserModel.create({
      id: `usr_${Math.random().toString(36).substring(2, 9)}`,
      email: email.toLowerCase(),
      faceDescriptor,
      pinHash,
      createdAt: new Date()
    });
    return newUser.toObject() as User;
  }

  async findByEmail(email: string): Promise<User | null> {
    await this.ensureConnected();
    const user = await UserModel.findOne({ email: email.toLowerCase() }).lean();
    return user ? (user as unknown as User) : null;
  }

  async findById(id: string): Promise<User | null> {
    await this.ensureConnected();
    const user = await UserModel.findOne({ id }).lean();
    return user ? (user as unknown as User) : null;
  }

  async findDevicesByUserId(userId: string): Promise<DeviceKey[]> {
    await this.ensureConnected();
    const devices = await DeviceKeyModel.find({ userId }).lean();
    return devices as unknown as DeviceKey[];
  }

  async findDeviceByCredentialID(credentialID: string): Promise<DeviceKey | null> {
    await this.ensureConnected();
    const device = await DeviceKeyModel.findOne({ credentialID }).lean();
    if (!device) return null;
    // Mongo/lean() can hand back the Buffer field as a BSON Binary-like object
    // depending on driver version — normalize it back to a real Buffer so the
    // WebAuthn library's curve math gets the bytes it expects.
    return {
      ...(device as any),
      credentialPublicKey: Buffer.isBuffer((device as any).credentialPublicKey)
        ? (device as any).credentialPublicKey
        : Buffer.from((device as any).credentialPublicKey?.buffer ?? (device as any).credentialPublicKey)
    } as unknown as DeviceKey;
  }

  async saveDeviceKey(device: Omit<DeviceKey, 'id' | 'createdAt'>): Promise<DeviceKey> {
    await this.ensureConnected();
    const newDevice = await DeviceKeyModel.create({
      ...device,
      id: `dev_${Math.random().toString(36).substring(2, 9)}`,
      createdAt: new Date()
    });
    return newDevice.toObject() as DeviceKey;
  }

  async updateDeviceCounter(deviceId: string, newCounter: number): Promise<void> {
    await this.ensureConnected();
    await DeviceKeyModel.updateOne({ id: deviceId }, { $set: { counter: newCounter } });
  }

  async approveDevice(deviceId: string): Promise<void> {
    await this.ensureConnected();
    await DeviceKeyModel.updateOne({ id: deviceId }, { $set: { isVerified: true } });
  }

  // --- Emergency Path (Argon2id recovery) ---

  async setRecoverySalt(userId: string, salt: string): Promise<void> {
    await this.ensureConnected();
    await UserModel.updateOne({ id: userId }, { $set: { recoverySalt: salt } });
  }

  async setRecoveryVerifier(userId: string, proofHash: string, codeHashes: string[]): Promise<void> {
    await this.ensureConnected();
    await UserModel.updateOne(
      { id: userId },
      {
        $set: {
          recoveryVerifierHash: proofHash,
          recoveryBackupCodes: codeHashes.map(codeHash => ({ codeHash, used: false }))
        }
      }
    );
  }

  async consumeBackupCode(userId: string, codeHash: string): Promise<void> {
    await this.ensureConnected();
    await UserModel.updateOne(
      { id: userId, 'recoveryBackupCodes.codeHash': codeHash },
      { $set: { 'recoveryBackupCodes.$.used': true, 'recoveryBackupCodes.$.usedAt': new Date() } }
    );
  }

  // Force Passkey Re-enroll: wipes every device key for this user so the very
  // next successful registration lands as the sole (and thus auto-verified)
  // device, per WebAuthnService.verifyRegistration()'s existing logic.
  async dropAllDevicesForUser(userId: string): Promise<void> {
    await this.ensureConnected();
    await DeviceKeyModel.deleteMany({ userId });
  }
}