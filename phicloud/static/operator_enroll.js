"use strict";
const $ = (name) => document.getElementById(name);
let pending = null;
const tell = (message) => { $("status").textContent = message; };
const fromB64URL = (text) => {
  const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(bytes, char => char.charCodeAt(0));
};
const toB64URL = (data) => {
  let str = "";
  for (const num of new Uint8Array(data)) str += String.fromCharCode(num);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
async function send(path, data) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "omit",
    cache: "no-store",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data),
  });
  if (!response.ok) throw Error("Registration denied by local operator server");
  return response.json();
}
$("unlock").addEventListener("click", async () => {
  $("unlock").disabled = true;
  tell("Verifying local pairing...");
  try {
    if (!window.isSecureContext || !navigator.credentials?.create) {
      throw Error("Browser WebAuthn is unavailable in this context");
    }
    const code = $("pairing").value;
    if (!code) throw Error("Enter the one-use code from your terminal");
    pending = await send("/v1/enroll/start", {code});
    $("pairing").value = "";
    $("pairing").disabled = true;
    $("operator").textContent = pending.operator;
    $("ceremony").hidden = false;
    tell("Operator pairing confirmed. Review the operator ID, then register.");
  } catch (error) {
    tell(error.message);
    $("unlock").disabled = false;
  }
});
$("register").addEventListener("click", async () => {
  if (!pending) return;
  $("register").disabled = true;
  tell("Requesting your authenticator. Complete its user-verification prompt.");
  try {
    const options = pending.options;
    options.challenge = fromB64URL(options.challenge);
    options.user.id = fromB64URL(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(
        item => ({...item, id: fromB64URL(item.id)})
      );
    }
    const cred = await navigator.credentials.create({publicKey: options});
    if (!cred || cred.type !== "public-key") throw Error("No passkey was created");
    const serialized = {
      id: cred.id,
      rawId: toB64URL(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: toB64URL(cred.response.clientDataJSON),
        attestationObject: toB64URL(cred.response.attestationObject),
        transports: cred.response.getTransports?.() || [],
      },
      clientExtensionResults: cred.getClientExtensionResults?.() || {},
    };
    const result = await send("/v1/enroll/finish", {
      session: pending.session, credential: serialized,
    });
    if (!result.enrolled || result.execution_authority) {
      throw Error("Unexpected registration result");
    }
    tell("Passkey registration verified for this local operator. No action was authorized.");
    pending = null;
  } catch (error) {
    tell(error.message + " This one-use ceremony is closed. Restart from your terminal.");
    pending = null;
  }
});
