import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Mail, KeyRound, ScanFace, ArrowRight, Loader2, Fingerprint, ShieldCheck } from 'lucide-react';
import { authApi } from '../lib/authApi';
import { loadFaceModels, captureFaceDescriptor } from '../lib/faceCapture';
import { performPasskeyAuthentication, performPasskeyRegistration } from '../lib/webauthn';

type Mode = 'login' | 'signup';
type LoginStage = 'face' | 'pin';
type Tone = 'error' | 'success' | 'info';

export default function Auth() {
  const [mode, setMode] = useState<Mode>('login');
  const [loginStage, setLoginStage] = useState<LoginStage>('face');

  const [email, setEmail] = useState('');
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');

  const [modelsReady, setModelsReady] = useState(false);
  const [cameraOn, setCameraOn] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);

  const [attemptsRemaining, setAttemptsRemaining] = useState<number | null>(null);
  const [partialToken, setPartialToken] = useState<string | null>(null);

  const [layer2Loading, setLayer2Loading] = useState(false);
  const [finalToken, setFinalToken] = useState<string | null>(null);

  const [showDeviceReg, setShowDeviceReg] = useState(false);
  const [deviceName, setDeviceName] = useState('');
  const [deviceRegLoading, setDeviceRegLoading] = useState(false);

  const [message, setMessage] = useState('');
  const [tone, setTone] = useState<Tone>('info');

  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  useEffect(() => {
    loadFaceModels()
      .then(() => setModelsReady(true))
      .catch(() => {
        setTone('error');
        setMessage('Could not load facial recognition models — check that /models is being served.');
      });

    return () => stopCamera();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startCamera = useCallback(async () => {
    if (streamRef.current) return;
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' } });
    streamRef.current = stream;
    if (videoRef.current) {
      videoRef.current.srcObject = stream;
      await videoRef.current.play();
    }
    setCameraOn(true);
  }, []);

  const stopCamera = () => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    setCameraOn(false);
  };

  const resetFlow = () => {
    setLoginStage('face');
    setAttemptsRemaining(null);
    setPartialToken(null);
    setFinalToken(null);
    setShowDeviceReg(false);
    setDeviceName('');
    setPin('');
    setConfirmPin('');
    setMessage('');
    stopCamera();
  };

  const switchMode = (next: Mode) => {
    setMode(next);
    resetFlow();
  };

  const captureLiveDescriptor = async (): Promise<number[]> => {
    await startCamera();
    setScanning(true);
    // brief pause so the camera has focused before we grab a frame
    await new Promise((r) => setTimeout(r, 700));
    const descriptor = await captureFaceDescriptor(videoRef.current!);
    setScanning(false);
    if (!descriptor) {
      throw new Error('No face detected. Look directly at the camera and try again.');
    }
    return descriptor;
  };

  // --- Signup: enroll face + confirmed PIN ---
  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!modelsReady) {
      setTone('error');
      setMessage('Facial recognition models are still loading — try again in a moment.');
      return;
    }
    if (pin !== confirmPin) {
      setTone('error');
      setMessage('PIN and confirmation do not match.');
      return;
    }
    if (!/^\d{4,6}$/.test(pin)) {
      setTone('error');
      setMessage('PIN must be 4 to 6 digits.');
      return;
    }

    setLoading(true);
    setMessage('');
    try {
      const descriptor = await captureLiveDescriptor();
      const result = await authApi.signup(email, descriptor, pin, confirmPin);
      if (!result.success) throw new Error(result.message || 'Signup failed.');

      setTone('success');
      setMessage('Account created — face and PIN enrolled. Log in, then set up a passkey for this device.');
      stopCamera();
      setMode('login');
      setPin('');
      setConfirmPin('');
    } catch (err: any) {
      setTone('error');
      setMessage(err.message || 'Signup failed.');
    } finally {
      setLoading(false);
      setScanning(false);
    }
  };

  // --- Login, Layer 1 path A: face match ---
  const handleFaceLogin = async () => {
    if (!email) {
      setTone('error');
      setMessage('Enter your email first.');
      return;
    }
    if (!modelsReady) {
      setTone('error');
      setMessage('Facial recognition models are still loading — try again in a moment.');
      return;
    }

    setLoading(true);
    setMessage('');
    try {
      const descriptor = await captureLiveDescriptor();
      const result = await authApi.loginFace(email, descriptor);

      if (result.success && result.partialToken) {
        setPartialToken(result.partialToken);
        setTone('success');
        setMessage('Face verified — Layer 1 cleared. Ready for Layer 2.');
        stopCamera();
        return;
      }

      if (result.requiresPin) {
        setLoginStage('pin');
        setAttemptsRemaining(0);
        setTone('error');
        setMessage('Face not recognized after 3 attempts. Enter your PIN instead.');
        stopCamera();
        return;
      }

      setAttemptsRemaining(result.attemptsRemaining ?? null);
      setTone('error');
      setMessage(`Face not recognized. ${result.attemptsRemaining ?? 0} attempt(s) remaining.`);
    } catch (err: any) {
      setTone('error');
      setMessage(err.message || 'Face verification failed.');
    } finally {
      setLoading(false);
      setScanning(false);
    }
  };

  // --- Login, Layer 1 path B: PIN fallback (only reachable after 3 face fails) ---
  const handlePinLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    try {
      const result = await authApi.loginPin(email, pin);

      if (result.redirectToLogin) {
        setTone('error');
        setMessage(result.message || 'Too many failed PIN attempts. Please start over.');
        resetFlow();
        return;
      }

      if (!result.success || !result.partialToken) {
        setAttemptsRemaining(result.attemptsRemaining ?? null);
        throw new Error(result.message || 'Incorrect PIN.');
      }
      setPartialToken(result.partialToken);
      setTone('success');
      setMessage('PIN verified — Layer 1 cleared. Ready for Layer 2.');
    } catch (err: any) {
      setTone('error');
      setMessage(err.message || 'PIN verification failed.');
    } finally {
      setLoading(false);
    }
  };

  // --- Layer 2: WebAuthn passkey login for an already-registered device ---
  // Deliberately a single explicit ceremony triggered by a real button click —
  // no auto-chaining into registration if none exists. That silent chaining
  // (create() immediately followed by get()) was fragile and is why Layer 2
  // used to fail with a generic error. If there's no passkey yet, the user
  // sees "Register a passkey instead" and picks it themselves.
  const handleLayer2Verify = async () => {
    if (!partialToken) return;
    setLayer2Loading(true);
    setMessage('');
    try {
      const options = await authApi.getLoginOptions(partialToken);
      const assertionResponse = await performPasskeyAuthentication(options);
      const result = await authApi.verifyLogin(partialToken, assertionResponse);

      if (!result.success || !result.token) {
        throw new Error(result.message || 'Passkey verification failed.');
      }

      setFinalToken(result.token);
      setTone('success');
      setMessage('Passkey verified. Layer 2 cleared — fully signed in.');
    } catch (err: any) {
      setTone('error');
      setMessage(describeWebAuthnError(err));
    } finally {
      setLayer2Loading(false);
    }
  };

  // --- Layer 2: enroll this device's passkey (first-time setup) ---
  const handleDeviceRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!partialToken) return;
    setDeviceRegLoading(true);
    setMessage('');
    try {
      const options = await authApi.getRegistrationOptions(partialToken);
      const attestationResponse = await performPasskeyRegistration(options);
      const outcome = await authApi.verifyRegistration(partialToken, deviceName, attestationResponse);

      setTone('success');
      setMessage(
        outcome.status === 'PENDING_CROSS_APPROVAL'
          ? 'Device registered — pending approval from an already-verified device.'
          : 'Device registered and active. Sign in with it now to finish.'
      );
      setShowDeviceReg(false);
      setDeviceName('');
    } catch (err: any) {
      setTone('error');
      setMessage(describeWebAuthnError(err));
    } finally {
      setDeviceRegLoading(false);
    }
  };

  const toneClasses: Record<Tone, string> = {
    error: 'border-red-200 bg-red-50 text-red-700',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    info: 'border-blue-200 bg-blue-50 text-blue-700',
  };

  return (
    <div className="min-h-screen bg-white text-slate-900 flex font-sans selection:bg-blue-600 selection:text-white">

      {/* LEFT COLUMN: Blue brand panel */}
      <div className="hidden lg:flex lg:w-[55%] relative overflow-hidden bg-gradient-to-br from-blue-600 to-blue-800 flex-col justify-between p-8 md:p-12 lg:p-16 xl:p-24">
        <div className="absolute inset-0 bg-grid-white/[0.06] bg-[size:32px_32px]" />
        <div className="absolute -top-24 -right-24 h-96 w-96 rounded-full bg-blue-400/20 blur-3xl" />
        <div className="absolute -bottom-32 -left-16 h-96 w-96 rounded-full bg-blue-300/10 blur-3xl" />

        <div className="flex items-center gap-2 relative z-10">
          <div className="h-9 w-9 rounded-xl bg-white flex items-center justify-center font-bold text-blue-700 shadow-lg">
            A
          </div>
          <span className="text-xl font-bold tracking-tight text-white">Auth</span>
        </div>

        <div className="w-full max-w-lg my-auto relative z-10 backdrop-blur-xl bg-white/10 border border-white/20 rounded-2xl p-8 md:p-12 shadow-2xl">
          <h2 className="text-3xl font-extrabold text-white tracking-tight mb-4">
            Next-Gen Cryptographic Security
          </h2>
          <p className="text-base text-blue-50 leading-relaxed">
            Layer 1 confirms it's you: a live face scan compared against your enrolled
            descriptor, with a 4–6 digit PIN as fallback once face matching fails three
            times in a row. Once Layer 1 clears, Layer 2 requires a hardware-backed
            passkey — an ECDSA P-256 credential bound to your device's secure enclave
            (Windows Hello, Touch ID, or similar), verified with its own replay-protected
            signature counter — before a session is ever issued.
          </p>
        </div>
      </div>

      {/* RIGHT COLUMN: Form Container */}
      <div className="w-full lg:w-[45%] flex flex-col justify-between p-8 md:p-12 lg:p-16 xl:p-24 relative z-10 bg-white border-l border-slate-200">

        <div className="flex items-center gap-2 lg:hidden">
          <div className="h-9 w-9 rounded-xl bg-blue-600 flex items-center justify-center font-bold text-white">
            A
          </div>
          <span className="text-xl font-bold tracking-tight text-slate-900">Auth</span>
        </div>

        <div className="w-full max-w-md mx-auto my-auto py-12">
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-slate-900 mb-2">
              {mode === 'login' ? 'Welcome back' : 'Enroll your identity'}
            </h1>
            <p className="text-sm text-slate-500">
              {mode === 'login'
                ? "We'll try your face first — if that doesn't work three times, you can use your PIN."
                : 'We need your email, a live face capture, and a PIN as a fallback.'}
            </p>
          </div>

          {/* Camera preview — shown whenever we're mid face-capture flow */}
          {(mode === 'signup' || (mode === 'login' && loginStage === 'face' && !partialToken)) && (
            <div className="mb-6 rounded-xl overflow-hidden border border-slate-200 bg-slate-50 relative aspect-video">
              <video
                ref={videoRef}
                muted
                playsInline
                className={`w-full h-full object-cover ${cameraOn ? 'opacity-100' : 'opacity-0'}`}
              />
              {!cameraOn && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-400 gap-2">
                  <ScanFace className="h-8 w-8" />
                  <span className="text-xs">Camera preview appears here</span>
                </div>
              )}
              {scanning && (
                <div className="absolute inset-0 flex items-center justify-center bg-slate-900/30">
                  <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
                </div>
              )}
            </div>
          )}

          {/* --- SIGNUP FORM --- */}
          {mode === 'signup' && (
            <form onSubmit={handleSignup} className="space-y-5">
              <Field icon={<Mail className="h-5 w-5" />} type="email" required value={email}
                onChange={setEmail} placeholder="you@example.com" label="Email Address" />
              <Field icon={<KeyRound className="h-5 w-5" />} type="password" required value={pin}
                onChange={setPin} placeholder="4-6 digit PIN" label="Backup PIN" />
              <Field icon={<KeyRound className="h-5 w-5" />} type="password" required value={confirmPin}
                onChange={setConfirmPin} placeholder="Confirm PIN" label="Confirm PIN" />

              <SubmitButton loading={loading} label="Scan Face & Create Account" />
            </form>
          )}

          {/* --- LOGIN FORM: face stage --- */}
          {mode === 'login' && loginStage === 'face' && !partialToken && (
            <div className="space-y-5">
              <Field icon={<Mail className="h-5 w-5" />} type="email" required value={email}
                onChange={setEmail} placeholder="you@example.com" label="Email Address" />

              {attemptsRemaining !== null && (
                <p className="text-xs text-amber-600">{attemptsRemaining} face attempt(s) remaining before PIN fallback unlocks.</p>
              )}

              <button
                type="button"
                onClick={handleFaceLogin}
                disabled={loading}
                className="w-full mt-2 bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded-xl flex items-center justify-center gap-2 group transition-all duration-200 shadow-lg shadow-blue-600/10 hover:shadow-blue-600/20 active:scale-[0.99] disabled:opacity-70"
              >
                {loading ? 'Scanning...' : 'Scan Face to Sign In'}
                <ScanFace className="h-5 w-5 group-hover:scale-110 transition-transform" />
              </button>
            </div>
          )}

          {/* --- LOGIN FORM: PIN fallback stage --- */}
          {mode === 'login' && loginStage === 'pin' && !partialToken && (
            <form onSubmit={handlePinLogin} className="space-y-5">
              <Field icon={<KeyRound className="h-5 w-5" />} type="password" required value={pin}
                onChange={setPin} placeholder="Your backup PIN" label="Backup PIN" />
              {attemptsRemaining !== null && (
                <p className="text-xs text-amber-600">{attemptsRemaining} PIN attempt(s) remaining before you'll need to start over.</p>
              )}
              <SubmitButton loading={loading} label="Verify PIN" />
              <button
                type="button"
                onClick={resetFlow}
                className="w-full text-xs text-slate-400 hover:text-slate-600 transition-colors"
              >
                Start over
              </button>
            </form>
          )}

          {/* --- LAYER 1 CLEARED, LAYER 2 PENDING --- */}
          {partialToken && !finalToken && (
            <div className="rounded-xl border border-blue-200 bg-blue-50 p-6 text-sm space-y-4">
              <p className="font-semibold text-blue-700">Layer 1 cleared. One more step.</p>

              {!showDeviceReg ? (
                <div className="space-y-3">
                  <button
                    type="button"
                    onClick={handleLayer2Verify}
                    disabled={layer2Loading}
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-70"
                  >
                    {layer2Loading ? (
                      <Loader2 className="h-5 w-5 animate-spin" />
                    ) : (
                      <Fingerprint className="h-5 w-5" />
                    )}
                    {layer2Loading ? 'Waiting for passkey...' : 'Sign In with Passkey'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowDeviceReg(true)}
                    className="w-full text-xs text-slate-500 hover:text-slate-700 transition-colors"
                  >
                    First time on this device? Register a passkey instead
                  </button>
                </div>
              ) : (
                <form onSubmit={handleDeviceRegister} className="space-y-3">
                  <Field icon={<Fingerprint className="h-5 w-5" />} type="text" required value={deviceName}
                    onChange={setDeviceName} placeholder="e.g. My Laptop" label="Device Name" />
                  <button
                    type="submit"
                    disabled={deviceRegLoading}
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-70"
                  >
                    {deviceRegLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : <Fingerprint className="h-5 w-5" />}
                    {deviceRegLoading ? 'Creating passkey...' : 'Create Passkey for This Device'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowDeviceReg(false)}
                    className="w-full text-xs text-slate-400 hover:text-slate-600 transition-colors"
                  >
                    Back
                  </button>
                </form>
              )}
            </div>
          )}

          {/* --- LAYER 2 CLEARED --- */}
          {finalToken && (
            <div className="rounded-xl border border-blue-200 bg-blue-50 p-6 text-sm text-blue-700 space-y-2">
              <div className="flex items-center gap-2 font-semibold">
                <ShieldCheck className="h-5 w-5" />
                Fully signed in.
              </div>
              <p className="text-slate-500 break-all text-xs">Session token: {finalToken}</p>
            </div>
          )}

          {message && (
            <div className={`mt-4 rounded-lg border px-4 py-3 text-sm ${toneClasses[tone]}`}>
              {message}
            </div>
          )}

          <div className="mt-8 text-center">
            <p className="text-sm text-slate-500">
              {mode === 'login' ? "Don't have an account yet?" : 'Already have an account?'}{' '}
              <button
                type="button"
                onClick={() => switchMode(mode === 'login' ? 'signup' : 'login')}
                className="text-blue-600 hover:text-blue-700 font-semibold focus:underline outline-none transition-colors ml-1"
              >
                {mode === 'login' ? 'Sign up' : 'Log in'}
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Surfaces the actual WebAuthn/network failure instead of a blanket message —
// the two DOMException names below cover the two most common real causes of a
// Layer 2 failure: the user backing out of the OS prompt, and an RPID/origin
// mismatch between this page and the backend's WebAuthnService env vars.
function describeWebAuthnError(err: any): string {
  if (err?.name === 'NotAllowedError') {
    return 'Passkey prompt was cancelled or timed out.';
  }
  if (err?.name === 'SecurityError') {
    return "Passkey ceremony failed: this page's origin doesn't match the server's RPID/EXPECTED_ORIGIN. Check those env vars on the backend.";
  }
  return err?.message || 'Passkey ceremony failed.';
}

function Field({
  icon, type, required, value, onChange, placeholder, label,
}: {
  icon: React.ReactNode; type: string; required?: boolean; value: string;
  onChange: (v: string) => void; placeholder: string; label: string;
}) {
  return (
    <div className="space-y-2">
      <label className="text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</label>
      <div className="relative">
        <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">{icon}</span>
        <input
          type={type}
          required={required}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full bg-white border border-slate-300 focus:border-blue-500 rounded-xl py-3.5 pl-12 pr-4 text-slate-900 placeholder-slate-400 outline-none transition-all duration-200 focus:ring-2 focus:ring-blue-500/20"
        />
      </div>
    </div>
  );
}

function SubmitButton({ loading, label }: { loading: boolean; label: string }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="w-full mt-2 bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded-xl flex items-center justify-center gap-2 group transition-all duration-200 shadow-lg shadow-blue-600/10 hover:shadow-blue-600/20 active:scale-[0.99] disabled:opacity-70"
    >
      {loading ? 'Processing...' : label}
      <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
    </button>
  );
}