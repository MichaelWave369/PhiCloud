"use strict";
const $ = id => document.getElementById(id);
let session = null;
let review = null;
const describe = [
  ["request_id","Request ID"],["scope","Scope"],["subject_issuer","Verified subject issuer"],
  ["subject_id","Verified subject ID"],["audience","Audience"],
  ["action","Action"],["resource","Resource"]
];
function announce(message) { $("status").textContent = message; }
function from64(value) {
  const encoded = value.replace(/-/g,"+").replace(/_/g,"/");
  const bytes = atob(encoded + "=".repeat((4-encoded.length%4)%4));
  return Uint8Array.from(bytes,c=>c.charCodeAt(0));
}
function to64(data) {
  let str = "";
  for (const x of new Uint8Array(data)) str += String.fromCharCode(x);
  return btoa(str).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function call(path, body) {
  const response = await fetch(path, {
    method:"POST", cache:"no-store", credentials:"omit",
    headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)
  });
  if (!response.ok) throw Error("The local operator server denied this review.");
  return response.json();
}
function showRequest(details) {
  $("request-fields").replaceChildren();
  const metadata = [
    ["Operator ID",details.operator],
    ["Signed review ID",details.review_id],
    ["Expires",new Date(details.expires_at_ms).toLocaleTimeString()]
  ];
  for (const [label,value] of metadata) {
    const term=document.createElement("dt"), definition=document.createElement("dd");
    term.textContent=label; definition.textContent=String(value);
    $("request-fields").append(term,definition);
  }
  for (const [field,label] of describe) {
    const term=document.createElement("dt"), definition=document.createElement("dd");
    term.textContent=label; definition.textContent=String(details.request[field]);
    $("request-fields").append(term,definition);
  }
}
$("unlock").addEventListener("click",async()=>{
  $("unlock").disabled=true;
  announce("Checking the one-use terminal pairing code...");
  try {
    if (!window.isSecureContext || !navigator.credentials?.get) {
      throw Error("This browser does not provide secure-context WebAuthn.");
    }
    const code=$("pairing").value;
    if (!code) throw Error("Enter the trusted local pairing code.");
    review=await call("/v1/review/unlock",{code});
    if (review.execution_authority || !review.session || !review.request) {
      throw Error("Invalid local review response.");
    }
    session=review.session;
    $("pairing").value="";
    $("unlock-section").hidden=true;
    showRequest(review);
    $("review-section").hidden=false;
    announce("Read the full signed request, then explicitly confirm or decline.");
  } catch (err) {
    announce(err.message);
    $("unlock").disabled=false;
  }
});
$("ack").addEventListener("change",()=>{
  $("approve").disabled=!$("ack").checked || !session;
});
$("approve").addEventListener("click",async()=>{
  if (!session || !$("ack").checked) return;
  $("approve").disabled=true;
  $("decline").disabled=true;
  announce("Requesting a fresh, one-use WebAuthn challenge...");
  try {
    const options=await call("/v1/review/challenge",{
      session, acknowledged:true
    });
    if (options.rpId!=="localhost" || options.userVerification!=="required") {
      throw Error("Unexpected relying-party configuration.");
    }
    options.challenge=from64(options.challenge);
    options.allowCredentials=options.allowCredentials.map(
      credential=>({...credential,id:from64(credential.id)})
    );
    announce("Use your registered passkey now. A verified assertion will record only this review.");
    const proof=await navigator.credentials.get({publicKey:options});
    if (!proof || proof.type!=="public-key") {
      throw Error("The passkey did not return an assertion.");
    }
    const assertion={
      id:proof.id,rawId:to64(proof.rawId),type:proof.type,
      response:{
        authenticatorData:to64(proof.response.authenticatorData),
        clientDataJSON:to64(proof.response.clientDataJSON),
        signature:to64(proof.response.signature),
        userHandle:proof.response.userHandle?to64(proof.response.userHandle):null
      },
      clientExtensionResults:proof.getClientExtensionResults?.()||{}
    };
    const outcome=await call("/v1/review/complete",{session,assertion});
    if (!outcome.review_recorded || outcome.execution_authority) {
      throw Error("The local review outcome was not accepted.");
    }
    announce("Signed + user-verified review recorded. No resource or PhiOS effect was executed.");
  } catch(err) {
    announce(err.message+" This one-shot challenge cannot be reused. Restart from a trusted operator terminal.");
  } finally {
    session=null;
    review=null;
    $("ack").disabled=true;
  }
});
$("decline").addEventListener("click",async()=>{
  if (!session) return;
  $("approve").disabled=true;
  $("decline").disabled=true;
  try {
    const outcome=await call("/v1/review/decline",{session});
    if (!outcome.declined || outcome.execution_authority) {
      throw Error("Unexpected decline response.");
    }
    announce("Review declined. The pending approval was burned without an effect.");
  } catch(err) {
    announce(err.message);
  } finally {
    session=null;
    review=null;
    $("ack").disabled=true;
  }
});
