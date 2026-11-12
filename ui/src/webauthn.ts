// Passkeys in the browser: the server's options (WebAuthn's JSON forms, with
// binary values as base64url) into what `navigator.credentials` takes, and
// its credentials back into what the server checks.

import type { Assertion, Registration } from "./session";

function decode(text: string): ArrayBuffer {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function encode(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether this browser can use passkeys at all. */
export function supported(): boolean {
  return typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

type Descriptor = { type: "public-key"; id: string };

/** Makes a passkey, as the server's creation options say. */
export async function register(options: object): Promise<Registration> {
  const o = options as Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    excludeCredentials: Descriptor[];
  };
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...o,
      challenge: decode(o.challenge),
      user: { ...o.user, id: decode(o.user.id) },
      excludeCredentials: o.excludeCredentials.map((c) => ({ type: c.type, id: decode(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("no passkey was made");
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: encode(credential.rawId),
    client_data_json: encode(response.clientDataJSON),
    attestation_object: encode(response.attestationObject),
  };
}

/** Signs with a passkey the user picks, as the server's request options say. */
export async function authenticate(options: object): Promise<Assertion> {
  const o = options as Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
    challenge: string;
    allowCredentials: Descriptor[];
  };
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...o,
      challenge: decode(o.challenge),
      allowCredentials: o.allowCredentials.map((c) => ({ type: c.type, id: decode(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("no passkey was used");
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: encode(credential.rawId),
    client_data_json: encode(response.clientDataJSON),
    authenticator_data: encode(response.authenticatorData),
    signature: encode(response.signature),
    user_handle: response.userHandle ? encode(response.userHandle) : null,
  };
}

/** What went wrong with a ceremony, for the person: the browser's own
 * errors are terse. */
export function explain(e: unknown): string {
  if (e instanceof DOMException) {
    if (e.name === "NotAllowedError") return "The passkey prompt was closed or timed out.";
    if (e.name === "InvalidStateError") return "This device has a passkey for you already.";
    if (e.name === "SecurityError") return "Passkeys don't work on this address: open the console at its own URL.";
  }
  return (e as Error).message;
}

/** A name for a new passkey: the kind of device, as far as the browser says. */
export function deviceName(): string {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return "iPhone or iPad";
  if (/Android/.test(ua)) return "Android";
  if (/Mac OS X/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows";
  if (/Linux/.test(ua)) return "Linux";
  return "Passkey";
}
