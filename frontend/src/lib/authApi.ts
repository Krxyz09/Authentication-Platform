async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`/api/auth${path}`, {
    ...init,
    headers,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.message || data?.error || 'Request failed');
  }

  return data as T;
}

export const authApi = {
  // Enrolls a new user with a facial descriptor + a confirmed PIN.
  // pinConfirm must match pin — the backend rejects signup otherwise.
  signup: (email: string, faceDescriptor: number[], pin: string, pinConfirm: string) =>
    requestJson<{ success: boolean; userId?: string; message?: string }>('/signup', {
      method: 'POST',
      body: JSON.stringify({ email, faceDescriptor, pin, pinConfirm }),
    }),

  // Layer 1, path A: face match (primary). requiresPin=true means 3 attempts
  // have been exhausted and the caller must fall back to loginPin.
  loginFace: (email: string, faceDescriptor: number[]) =>
    requestJson<{
      success: boolean;
      partialToken?: string;
      requiresPin?: boolean;
      attemptsRemaining?: number;
      message?: string;
    }>('/login/step1/face', {
      method: 'POST',
      body: JSON.stringify({ email, faceDescriptor }),
    }),

  // Layer 1, path B: PIN fallback. Backend rejects this until 3 face attempts have
  // failed. redirectToLogin=true means the 3rd PIN attempt also failed — the whole
  // login attempt was invalidated server-side and the caller must restart from face.
  loginPin: (email: string, pin: string) =>
    requestJson<{
      success: boolean;
      partialToken?: string;
      redirectToLogin?: boolean;
      attemptsRemaining?: number;
      message?: string;
    }>('/login/step1/pin', {
      method: 'POST',
      body: JSON.stringify({ email, pin }),
    }),

  // Layer 2, WebAuthn: registration options for enrolling a new passkey on this device.
  getRegistrationOptions: (partialToken: string) =>
    requestJson<any>('/register-options', {
      method: 'POST',
      headers: { Authorization: `Bearer ${partialToken}` },
    }),

  // Layer 2, WebAuthn: verifies the browser's attestation response and saves the device.
  verifyRegistration: (partialToken: string, deviceName: string, response: unknown) =>
    requestJson<{ success: boolean; status?: string; deviceId?: string; message?: string }>('/register-verify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${partialToken}` },
      body: JSON.stringify({ deviceName, response }),
    }),

  // Layer 2, WebAuthn: authentication (login) challenge for an already-registered device.
  getLoginOptions: (partialToken: string) =>
    requestJson<any>('/login-options', {
      method: 'POST',
      headers: { Authorization: `Bearer ${partialToken}` },
    }),

  // Layer 2, WebAuthn: verifies the browser's assertion response and, on success,
  // issues the final fully-cleared session token.
  verifyLogin: (partialToken: string, response: unknown) =>
    requestJson<{ success: boolean; token?: string; message?: string }>('/login-verify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${partialToken}` },
      body: JSON.stringify({ response }),
    }),
};