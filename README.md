# Auhentication Platform
Instead of relying on a single authentication factor, I have combined **facial verification** with **WebAuthn passkeys**, providing a seamless login experience while significantly improving account security.

---

## ✨ Features

- 🔒 Two independent authentication layers
- 👤 Facial recognition using **face-api.js**
- 🔑 WebAuthn/FIDO2 passkey authentication
- 📱 Hardware-backed platform authenticators
- 🔄 Secure JWT-based multi-stage authentication
- 🔐 PIN fallback after multiple failed facial attempts
- 🛡️ Counter-based replay attack protection
- 💾 MongoDB persistence for users and credentials
- ⚡ Fully built with React, Express, and TypeScript

---

# Why Two Layers?

Traditional authentication methods usually rely on a single point of trust. If that trust is compromised, the account becomes vulnerable.

This authentication into two independent verification layers.

### Layer 1 — Identity Verification

A lightweight identity check using **face-api.js** performs facial descriptor comparison directly in the browser.

If facial verification fails three consecutive times, users may authenticate using their registered PIN.

This layer answers:

> **"Is this likely the legitimate user?"**

---

### Layer 2 — Hardware-backed Authentication

Once identity is established, the application performs **WebAuthn authentication** using platform authenticators such as:

- Face ID
- Touch ID
- Windows Hello
- Android StrongBox

The device signs a cryptographic challenge using a private key securely stored inside trusted hardware (TPM / Secure Enclave / StrongBox).

The private key **never leaves the device**, making authentication resistant to phishing and credential theft.

This layer answers:

> **"Can this device prove ownership of its private key?"**

---

# 🏗 Architecture

```
Client (React + Vite)
│
├── face-api.js
│     Facial descriptor extraction
│
├── WebAuthn API
│     Platform authenticator
│
└── Auth API
      JWT-based authentication flow


Backend (Express + TypeScript)
│
├── Layer 1 Service
│     Face verification
│     PIN validation
│     Failed-attempt tracking
│
├── Layer 2 Service
│     WebAuthn registration
│     WebAuthn authentication
│     Counter verification
│
└── User Repository
      MongoDB persistence


MongoDB
│
├── User
│
└── Device Credentials
```

---

# 🛠 Tech Stack

## Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- face-api.js
- Native WebAuthn API

## Backend

- Node.js
- Express.js
- TypeScript
- MongoDB
- Mongoose
- @simplewebauthn/server
- bcrypt
- JWT

---

# 📂 Project Structure

```
backend/
│
├── config/
├── models/
├── modules/
│   ├── auth/
│   └── user/
├── types/
├── app.ts
└── server.ts


frontend/
│
├── views/
├── lib/
│
└── public/
    └── models/
```

---

# 🔐 Security Highlights

- Facial verification is performed locally using facial descriptors.
- PIN authentication becomes available only after three failed facial attempts.
- WebAuthn uses hardware-backed platform authenticators.
- Private keys never leave the user's device.
- Only public keys are stored on the server.
- JWTs enforce staged authentication (`layer1Cleared` → `layer2Cleared`).
- Counter validation protects against replay attacks.
- Failed facial verification attempts are tracked server-side.
- Restricted to platform authenticators with required user verification.

---

# ⚙️ Installation

## Backend

```bash
cd backend
npm install
```

Create a `.env` file inside the backend directory.

```env
PORT=3000
MONGODB_URI=mongodb://127.0.0.1:27017/optimal_primes
JWT_SECRET=your_secret
RPID=localhost
EXPECTED_ORIGIN=http://localhost:5173
```

Run the backend:

```bash
npx tsx src/server.ts
```

---

## Frontend

```bash
cd frontend
npm install
npm install face-api.js
```


Run the frontend:

```bash
npm run dev
```



# 🚀 Future Improvements

- Liveness detection for facial verification
- Multi-device passkey management
- Administrative approval workflows
- Device trust management
- Risk-based adaptive authentication
- Audit logs and security analytics

---


