import { Router, Request, Response } from 'express';
import { Layer1Service } from './layer1.service.js';
import { WebAuthnService } from './webauthn.service.js';
import jwt from 'jsonwebtoken';
import { JWTPayload } from '../../types/index.js';

export const authRouter = Router();
const l1Service = new Layer1Service();
const webAuthnService = new WebAuthnService();
const JWT_SECRET = process.env.JWT_SECRET || 'tally-secret-key-signature';

// Helper function to extract user details from partial tokens.
// Explicitly requires layer1Cleared=true so Layer 2 (WebAuthn) can never run off a
// malformed or stale token that happens to decode successfully.
const validatePartialSession = (req: Request, res: Response): JWTPayload | null => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing temporary session token context.' });
    return null;
  }
  try {
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET) as JWTPayload;
    if (!payload.layer1Cleared) {
      res.status(403).json({ error: 'Layer 1 (face or PIN) must be completed before Layer 2.' });
      return null;
    }
    return payload;
  } catch {
    res.status(401).json({ error: 'Session mutated or expired.' });
    return null;
  }
};

// --- Signup: enroll face descriptor + confirmed PIN ---
// The PIN is submitted twice (pin + pinConfirm); Layer1Service rejects the
// signup if they don't match, before anything is hashed or stored. Only the
// bcrypt hash ever reaches MongoDB — never the raw PIN.
authRouter.post('/signup', async (req, res) => {
  try {
    const { email, faceDescriptor, pin, pinConfirm } = req.body;
    const user = await l1Service.signup(email, faceDescriptor, pin, pinConfirm);
    res.json({ success: true, userId: user.id });
  } catch (err: any) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// --- Layer 1, path A: face match (primary) ---
authRouter.post('/login/step1/face', async (req, res) => {
  try {
    const { email, faceDescriptor } = req.body;
    const result = await l1Service.verifyFace(email, faceDescriptor);
    res.json(result);
  } catch (err: any) {
    res.status(401).json({ success: false, message: err.message });
  }
});

// --- Layer 1, path B: PIN fallback (only unlocks after 3 failed face attempts) ---
// A 3rd failed PIN attempt returns redirectToLogin: true — the client should
// discard all local login state and send the user back to the main login page
// to restart from face verification.
authRouter.post('/login/step1/pin', async (req, res) => {
  try {
    const { email, pin } = req.body;
    const result = await l1Service.verifyPin(email, pin);
    res.json(result);
  } catch (err: any) {
    res.status(401).json({ success: false, message: err.message });
  }
});

// --- Layer 2, WebAuthn: passkey registration options ---
// Requires a valid Layer-1-cleared partial token — a device can only be
// enrolled once the user has proven themselves via face or PIN first.
authRouter.post('/register-options', async (req, res) => {
  const payload = validatePartialSession(req, res);
  if (!payload) return;

  try {
    const options = await webAuthnService.generateRegistrationOptionsForUser(payload.userId, payload.email);
    res.json(options);
  } catch (err: any) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// --- Layer 2, WebAuthn: passkey registration verification ---
authRouter.post('/register-verify', async (req, res) => {
  const payload = validatePartialSession(req, res);
  if (!payload) return;

  try {
    const { deviceName, response } = req.body;
    const outcome = await webAuthnService.verifyRegistration(payload.userId, deviceName, response);
    res.json({ success: true, ...outcome });
  } catch (err: any) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// --- Layer 2, WebAuthn: login challenge ---
authRouter.post('/login-options', async (req, res) => {
  const payload = validatePartialSession(req, res);
  if (!payload) return;

  try {
    const options = await webAuthnService.generateLoginChallenge(payload.userId);
    res.json(options);
  } catch (err: any) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// --- Layer 2, WebAuthn: login verification (issues the final, fully-cleared token) ---
authRouter.post('/login-verify', async (req, res) => {
  const payload = validatePartialSession(req, res);
  if (!payload) return;

  try {
    const result = await webAuthnService.verifyLogin(payload.userId, req.body.response);
    if (result.success) {
      const finalToken = jwt.sign(
        { userId: payload.userId, email: payload.email, layer1Cleared: true, layer2Cleared: true },
        JWT_SECRET,
        { expiresIn: '8h' }
      );
      res.json({ success: true, token: finalToken });
    } else {
      res.status(400).json({ success: false, message: 'Crypto verification failed.' });
    }
  } catch (err: any) {
    res.status(400).json({ success: false, message: err.message });
  }
});