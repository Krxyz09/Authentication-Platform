import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/browser';

/**
 * Passkey registration (Layer 2 enrollment).
 *
 * `optionsJSON` is exactly what the backend's /register-options endpoint
 * returns — it comes straight out of @simplewebauthn/server's
 * generateRegistrationOptions(), so no manual base64url <-> ArrayBuffer
 * conversion is needed here. startRegistration() handles that, invokes
 * navigator.credentials.create() under the hood, and returns a JSON body
 * shaped exactly like what verifyRegistrationResponse() expects on the backend.
 */
export async function performPasskeyRegistration(
  optionsJSON: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  return startRegistration({ optionsJSON });
}

/**
 * Passkey authentication (Layer 2 login).
 *
 * Same idea as above but for the login ceremony: `optionsJSON` comes straight
 * from the backend's /login-options endpoint, and the returned response body
 * is exactly what the backend's /login-verify endpoint forwards into
 * verifyAuthenticationResponse().
 */
export async function performPasskeyAuthentication(
  optionsJSON: PublicKeyCredentialRequestOptionsJSON
): Promise<AuthenticationResponseJSON> {
  return startAuthentication({ optionsJSON });
}