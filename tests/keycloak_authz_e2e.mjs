/**
 * PhiCloud R3: REAL Keycloak -> OAuth access token -> Python resource-server
 * introspection. No mock JWT verifier, no production identities.
 *
 * Clone the pinned PhiID fixture into integration/phiid and npm install it.
 * Start the Keycloak test realm using that fixture's Compose profile.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const fixture = await import('../integration/phiid/dev/keycloak/live-e2e.mjs');
const fixtureRequire = createRequire(new URL('../integration/phiid/package.json', import.meta.url));
const oidc = await import(pathToFileURL(fixtureRequire.resolve('openid-client')).href);
const ISSUER = 'http://127.0.0.1:8080/realms/phiid-dev';
const CLOUD = 'http://127.0.0.1:8769';
const AUDIENCE = 'phicloud-resource-dev';
const SCOPE = 'phicloud.profile.read';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

if (process.env.PHICLOUD_REAL_E2E !== '1' || process.env.NODE_ENV === 'production') {
  throw new Error('explicit localhost integration-test opt-in required');
}
if (!process.env.KC_BOOTSTRAP_ADMIN_PASSWORD || !process.env.KC_BOOTSTRAP_ADMIN_USERNAME) {
  throw new Error('ephemeral admin credentials required');
}

async function assertStatus(response, code, summary) {
  assert.equal(response.status, code, summary);
}

async function fetchAdmin(token, path, options = {}) {
  return fixture.adminJson(token, '/admin/realms/phiid-dev/' + path, options);
}
async function adminList(token, path) {
  const response = await fetchAdmin(token, path);
  await assertStatus(response, 200, 'Keycloak Admin list unavailable');
  return response.json();
}
async function addClient(token) {
  const client = {
    clientId: AUDIENCE,
    name: 'PhiCloud R3 confidential dev introspection resource',
    enabled: true, protocol: 'openid-connect',
    publicClient: false, clientAuthenticatorType: 'client-secret',
    standardFlowEnabled: false, directAccessGrantsEnabled: false,
    implicitFlowEnabled: false, serviceAccountsEnabled: false,
    bearerOnly: false, redirectUris: [], webOrigins: [],
  };
  const created = await fetchAdmin(token, 'clients', {
    method:'POST', body:JSON.stringify(client),
  });
  await assertStatus(created, 201, 'confidential dev resource client create failed');
  const matching = await adminList(token,'clients?clientId=' + AUDIENCE);
  assert.equal(matching.filter(item => item.clientId === AUDIENCE).length, 1);
  const id = matching.find(item => item.clientId === AUDIENCE).id;
  const secretResponse = await fetchAdmin(token, 'clients/' + id + '/client-secret');
  await assertStatus(secretResponse, 200, 'confidential client credential missing');
  const details = await secretResponse.json();
  assert.ok(typeof details.value === 'string' && details.value.length >= 32);
  return { id, secret: details.value };
}

async function addOptionalScope(token) {
  const created = await fetchAdmin(token, 'client-scopes', {
    method: 'POST',
    body: JSON.stringify({
      name:SCOPE, protocol:'openid-connect',
      description:'Only the read-only local PhiCloud R3 demo profile',
      attributes: {
        'include.in.token.scope': 'true',
        'display.on.consent.screen': 'true',
        'consent.screen.text': 'Read the local PhiCloud demo profile',
      },
      protocolMappers:[{
        name:'phicloud-audience',
        protocol:'openid-connect',
        protocolMapper:'oidc-audience-mapper',
        consentRequired:false,
        config:{
          'included.client.audience': AUDIENCE,
          'access.token.claim':'true',
          'id.token.claim':'false',
          'introspection.token.claim':'true',
        },
      }],
    }),
  });
  await assertStatus(created,201,'local profile scope create failed');
  const scopes = await adminList(token,'client-scopes');
  const match=scopes.find(item=>item.name===SCOPE);
  assert.ok(match?.id,'new Keycloak scope was not registered');

  const clients=await adminList(token,'clients?clientId=phiid-bff-dev');
  const phiid=clients.find(item=>item.clientId==='phiid-bff-dev');
  assert.ok(phiid?.id);
  const result=await fetchAdmin(token,
    'clients/'+phiid.id+'/optional-client-scopes/'+match.id,{method:'PUT'});
  await assertStatus(result,204,'optional scope could not be registered for PhiID');
  return match.id;
}

async function exchangeUserToken(clientId, callback, scopes, user) {
  const c=await oidc.discovery(new URL(ISSUER),clientId,
    {token_endpoint_auth_method:'none'},oidc.None(),
    {execute:[oidc.allowInsecureRequests],timeout:8});
  assert.equal(c.serverMetadata().issuer,ISSUER);
  const verifier=oidc.randomPKCECodeVerifier();
  const state=oidc.randomState();
  const nonce=oidc.randomNonce();
  const challenge=await oidc.calculatePKCECodeChallenge(verifier);
  const url=oidc.buildAuthorizationUrl(c,{
    redirect_uri:callback,
    scope:scopes,
    code_challenge:challenge,code_challenge_method:'S256',
    state,nonce,
  });
  const authCallback=await fixture.getKeycloakCode(url.href,callback,user);
  const tokens=await oidc.authorizationCodeGrant(c,authCallback,{
    pkceCodeVerifier:verifier,
    expectedState:state,
    expectedNonce:nonce,
    idTokenExpected:true,
  });
  assert.ok(typeof tokens.access_token === 'string' && tokens.access_token.length>80);
  assert.equal(tokens.claims().sub,user.userId);
  return tokens.access_token;
}

async function withPythonServer(secret, fn) {
  const child=spawn('python',['-m','phicloud.server','--port','8769'],{
    env:{
      ...process.env,
      PHICLOUD_ENABLE_OAUTH_DEV:'1',
      PHICLOUD_ENV:'test',
      PHICLOUD_OAUTH_CLIENT_SECRET:secret,
      PYTHONUNBUFFERED:'1',
    },
    stdio:['ignore','pipe','pipe'],
  });
  child.stdout.on('data',()=>{});
  child.stderr.on('data',()=>{});
  try {
    for(let attempt=0;attempt<45;attempt++){
      if(child.exitCode!==null || child.signalCode!==null) throw new Error('Python resource server exited');
      try{
        const r=await fetch(CLOUD+'/healthz',{signal:AbortSignal.timeout(1200)});
        if(r.status===200)return await fn();
      }catch{ /* wait for local server */ }
      await sleep(300);
    }
    throw new Error('Python resource server startup failure');
  } finally {
    if(child.exitCode===null && child.signalCode===null)child.kill('SIGTERM');
    if(child.exitCode===null && child.signalCode===null)
      await Promise.race([once(child,'exit'),sleep(2000)]);
  }
}

async function resourceRequest(token, path='/v1/private/profile') {
  return fetch(CLOUD+path,{
    redirect:'manual',
    signal:AbortSignal.timeout(9000),
    headers: token ? {Authorization:'Bearer '+token} : {},
  });
}

function checkInternalShield(token, secret, expected, consentFixture = true) {
  // Deliberately no bearer token in argv, URL, printed logs or source files.
  const result = spawnSync('python', ['tests/shield_identity_e2e.py'], {
    env: {
      ...process.env,
      PHICLOUD_OAUTH_CLIENT_SECRET: secret,
      PHICLOUD_SHIELD_CONSENT_FIXTURE: consentFixture ? '1' : '0',
      PHICLOUD_REAL_E2E: '1',
      NODE_ENV: 'test',
      PYTHONPATH: '.',
    },
    input: token,
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 0, 'local PhiShield integration subprocess failed');
  assert.equal(result.stdout.trim(), expected,
    'local PhiShield must derive identity from Keycloak and honor independent consent');
}

function checkR5OwnerReview(token, secret, expected, mode = 'approve') {
  // A REAL Keycloak token, but the terminal review is a synthetic CI input.
  // No bearer token or client secret in argv or diagnostic messages.
  const result = spawnSync('python', ['tests/owner_consent_e2e.py'], {
    env: {
      ...process.env,
      PHICLOUD_OAUTH_CLIENT_SECRET: secret,
      PHICLOUD_R5_REVIEW_FIXTURE: mode,
      PHICLOUD_REAL_E2E: '1',
      NODE_ENV: 'test',
      PYTHONPATH: '.',
    },
    input: token,
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 0, 'R5 in-process owner review check unavailable');
  assert.equal(result.stdout.trim(), expected,
    'R5 must enforce verified identity, owner binding and one-use review');
}

async function exercise(admin, user, secret) {
  await withPythonServer(secret, async()=>{
    const start=await resourceRequest(null);
    assert.equal(start.status,401,'private route must reject unauthenticated access');

    console.log('R3: real Keycloak user access token, optional scope and audience');
    const valid=await exchangeUserToken('phiid-bff-dev',
      'http://127.0.0.1:8786/auth/callback',
      'openid profile '+SCOPE,user);
    const permitted=await resourceRequest(valid);
    assert.equal(permitted.status,200,'real token with correct audience/scope rejected');
    const profile=await permitted.json();
    assert.equal(profile.authenticated,true);
    assert.equal(profile.authorized_audience,AUDIENCE);
    assert.equal(profile.authorized_scope,SCOPE);
    assert.equal(profile.cloud_storage_access,false);
    assert.equal(profile.mailbox_access,false);
    assert.equal(profile.phios_effect_authority,false);
    assert.ok(!JSON.stringify(profile).includes(user.username));

    console.log('R4: verified Keycloak subject to local PhiShield reference gate');
    checkInternalShield(valid, secret, 'CANDIDATE', true);
    checkInternalShield(valid, secret, 'DENY', false);

    console.log('R5: verified Keycloak identity with simulated one-use owner review');
    checkR5OwnerReview(valid, secret, 'DENY', 'deny');
    checkR5OwnerReview(valid, secret, 'CANDIDATE', 'approve');

    console.log('R3: wrong scope, wrong audience and ID-only flows denied');
    const noScope=await exchangeUserToken('phiid-bff-dev',
      'http://127.0.0.1:8786/auth/callback','openid profile',user);
    assert.equal((await resourceRequest(noScope)).status,401,
      'token without registered audience/scope was accepted');
    checkInternalShield(noScope, secret, 'DENY', true);
    checkR5OwnerReview(noScope, secret, 'DENY', 'approve');

    const mailToken=await exchangeUserToken('phimail-bff-dev',
      'http://127.0.0.1:5173/auth/phiid/callback','openid profile',user);
    assert.equal((await resourceRequest(mailToken)).status,401,
      'PhiMail token accidentally authorized PhiCloud demo');
    checkInternalShield(mailToken, secret, 'DENY', true);
    checkR5OwnerReview(mailToken, secret, 'DENY', 'approve');
    assert.equal((await resourceRequest('not-a-real-token-with-any-permissions')).status,401);

    console.log('R3: revoke upstream user session and require fresh introspection');
    const logout=await fetchAdmin(admin,'users/'+user.userId+'/logout',{method:'POST'});
    await assertStatus(logout,204,'Keycloak test user logout failed');
    // Keycloak token introspection must reflect session invalidation. No cache.
    const after=await resourceRequest(valid);
    assert.equal(after.status,401,'revoked real user token was accepted after Keycloak logout');
    checkInternalShield(valid, secret, 'DENY', true);
    checkR5OwnerReview(valid, secret, 'DENY', 'approve');
    console.log('PASS: genuine Keycloak token allowed only intended PhiCloud read scope, revoked session denied');
    console.log('PASS: R4 PhiShield internal integration requires real active subject, exact scope and independent consent fixture');
    console.log('PASS: R5 one-use owner review requires active Keycloak identity and exact simulated approval');
    console.log('BOUNDARY: no cloud data, file I/O, Gmail or PhiOS operations performed');
  });
}

async function main(){
  console.log('R3: waiting for real disposable Keycloak');
  await fixture.waitForKeycloak();
  console.log('R3: obtaining local test administrator credential');
  const admin=await fixture.adminToken();
  let user;
  try{
    console.log('R3: registering temporary confidential resource client');
    const resource=await addClient(admin);
    console.log('R3: configuring explicit local audience and optional scope');
    await addOptionalScope(admin);
    console.log('R3: creating disposable non-admin test identity');
    user=await fixture.createDisposableUser(admin);
    await exercise(admin,user,resource.secret);
  } finally{
    if(user?.userId) {
      const deleted=await fetchAdmin(admin,'users/'+user.userId,{method:'DELETE'});
      assert.equal(deleted.status,204,'disposable user cleanup failed');
    }
  }
}

// Node's fetch and AbortSignal.timeout can be unref'ed during early Docker
// startup. Keep the event loop alive until the bounded smoke test settles.
const liveLoop = setInterval(() => {}, 1000);
try {
  await main();
} catch (error) {
  // Never print raw OAuth callback URLs or token/credential-bearing errors.
  console.error('PhiCloud R3 real-provider smoke failed:',error?.name||'Error',
    error?.name==='AssertionError' ? 'contract assertion not met' : 'local integration unavailable');
  process.exitCode=1;
} finally {
  clearInterval(liveLoop);
}
