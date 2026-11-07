/**
 * PhiCloud R6: two ACTUAL Keycloak users and private SQLite tenant membership.
 * All identity, DB paths, scopes and users are disposable CI-only fixtures.
 * No mailbox, PhiVault files, OS effects or public identity endpoints.
 */
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createRequire} from 'node:module';
import {mkdtempSync,rmSync,copyFileSync,renameSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const fixture=await import('../integration/phiid/dev/keycloak/live-e2e.mjs');
const requireFromFixture=createRequire(new URL('../integration/phiid/package.json',import.meta.url));
const oidc=await import(pathToFileURL(requireFromFixture.resolve('openid-client')).href);

const ISSUER='http://127.0.0.1:8080/realms/phiid-dev';
const RESOURCE='phicloud-resource-dev';
const CLOUD='http://127.0.0.1:8769';
const READ='phicloud.tenant.read';
const WRITE='phicloud.tenant.write';
const CALLBACK='http://127.0.0.1:8786/auth/callback';
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));

if(process.env.PHICLOUD_TENANT_REAL_E2E!=='1'||
   process.env.PHIID_E2E_ENABLE!=='1'||
   process.env.NODE_ENV==='production'||
   !process.env.KC_BOOTSTRAP_ADMIN_USERNAME||
   !process.env.KC_BOOTSTRAP_ADMIN_PASSWORD)
  throw new Error('disposable local-only Keycloak fixture and opt-in required');

async function admin(token,path,opts={}) {
  return fixture.adminJson(token,'/admin/realms/phiid-dev/'+path,opts);
}
async function adminList(token,path) {
  const r=await admin(token,path);
  assert.equal(r.status,200,'Keycloak Admin list unavailable');
  return r.json();
}
async function createConfidentialResource(token) {
  const created=await admin(token,'clients',{
    method:'POST',body:JSON.stringify({
      clientId:RESOURCE,enabled:true,protocol:'openid-connect',
      publicClient:false,clientAuthenticatorType:'client-secret',
      standardFlowEnabled:false,implicitFlowEnabled:false,
      directAccessGrantsEnabled:false,serviceAccountsEnabled:false,
      redirectUris:[],webOrigins:[],
    }),
  });
  assert.equal(created.status,201,'resource client create');
  const list=await adminList(token,'clients?clientId='+RESOURCE);
  const found=list.find(item=>item.clientId===RESOURCE);
  assert.ok(found?.id);
  const response=await admin(token,'clients/'+found.id+'/client-secret');
  assert.equal(response.status,200);
  const secret=(await response.json()).value;
  assert.ok(typeof secret==='string'&&secret.length>=32);
  return secret;
}
async function configureScope(adminToken,scope) {
  const r=await admin(adminToken,'client-scopes',{
    method:'POST',body:JSON.stringify({
      name:scope,protocol:'openid-connect',
      description:'Disposable PhiCloud R6 test-only tenant operation',
      attributes:{
        'include.in.token.scope':'true',
        'display.on.consent.screen':'true',
        'consent.screen.text':'Review local tenant '+scope,
      },
      protocolMappers:[{
        name:'phicloud-resource-audience',
        protocol:'openid-connect',
        protocolMapper:'oidc-audience-mapper',
        consentRequired:false,
        config:{
          'included.client.audience':RESOURCE,
          'access.token.claim':'true',
          'id.token.claim':'false',
          'introspection.token.claim':'true',
        },
      }],
    }),
  });
  assert.equal(r.status,201,'optional resource scope registration');
  const scopes=await adminList(adminToken,'client-scopes');
  const found=scopes.find(item=>item.name===scope);
  assert.ok(found?.id);
  const clients=await adminList(adminToken,'clients?clientId=phiid-bff-dev');
  const client=clients.find(item=>item.clientId==='phiid-bff-dev');
  assert.ok(client?.id);
  const mapped=await admin(adminToken,
    'clients/'+client.id+'/optional-client-scopes/'+found.id,{method:'PUT'});
  assert.equal(mapped.status,204,'client optional resource scope assignment');
}
async function login(user,scopes) {
  const config=await oidc.discovery(new URL(ISSUER),'phiid-bff-dev',
    {token_endpoint_auth_method:'none'},oidc.None(),
    {execute:[oidc.allowInsecureRequests],timeout:8});
  assert.equal(config.serverMetadata().issuer,ISSUER);
  const verifier=oidc.randomPKCECodeVerifier();
  const state=oidc.randomState();
  const nonce=oidc.randomNonce();
  const challenge=await oidc.calculatePKCECodeChallenge(verifier);
  const url=oidc.buildAuthorizationUrl(config,{
    redirect_uri:CALLBACK,scope:'openid profile '+scopes,
    code_challenge:challenge,code_challenge_method:'S256',state,nonce,
  });
  const redirected=await fixture.getKeycloakCode(url.href,CALLBACK,user);
  const result=await oidc.authorizationCodeGrant(config,redirected,{
    pkceCodeVerifier:verifier,expectedState:state,expectedNonce:nonce,
    idTokenExpected:true,
  });
  assert.equal(result.claims().sub,user.userId);
  assert.ok(typeof result.access_token==='string'&&result.access_token.length>80);
  return result.access_token;
}
function tenantFixture(alice,bob) {
  const member=user=>({iss:ISSUER,sub:user.userId});
  return JSON.stringify({
    schema:'phicloud.local-tenant-demo.v0.1',
    tenants:[
      {id:'alpha-team',members:[member(alice),member(bob)]},
      {id:'beta-team',members:[member(bob)]},
    ],
  });
}
async function withPython(dbPath,secret,provision,action,fencePath=null) {
  const env={
    ...process.env,
    NODE_ENV:'test',
    PHICLOUD_ENV:'test',
    PHICLOUD_ENABLE_OAUTH_DEV:'1',
    PHICLOUD_ENABLE_TENANT_DEV:'1',
    PHICLOUD_OAUTH_CLIENT_SECRET:secret,
    PHICLOUD_TENANT_DB_PATH:dbPath,
    PYTHONUNBUFFERED:'1',
  };
  if(provision)env.PHICLOUD_TENANT_PROVISION_JSON=provision;
  else delete env.PHICLOUD_TENANT_PROVISION_JSON;
  if(fencePath) {
    env.PHICLOUD_ENABLE_FENCE_DEV='1';
    env.PHICLOUD_TENANT_FENCE_PATH=fencePath;
  }else{
    delete env.PHICLOUD_ENABLE_FENCE_DEV;
    delete env.PHICLOUD_TENANT_FENCE_PATH;
  }
  const child=spawn('python',['-m','phicloud.server','--port','8769'],{
    env,stdio:['ignore','pipe','pipe'],
  });
  let output='';
  // Buffer only static startup notices, not requests or OAuth tokens.
  child.stdout.on('data',chunk=>{output+=String(chunk).slice(0,250);});
  child.stderr.on('data',()=>{});
  try {
    for(let i=0;i<60;i++){
      if(child.exitCode!==null||child.signalCode!==null)
        throw new Error('Python local tenant server exited unexpectedly');
      try{
        const r=await fetch(CLOUD+'/healthz',{signal:AbortSignal.timeout(1000)});
        if(r.status===200){
          assert.ok(output.includes('R6 private synthetic tenant store enabled'),
            'R6 tenant store not explicitly enabled');
          return await action();
        }
      }catch(e){
        if(e?.name==='AssertionError')throw e;
      }
      await wait(250);
    }
    throw new Error('private tenant server startup timed out');
  }finally{
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    if(child.exitCode===null&&child.signalCode===null)
      await Promise.race([once(child,'exit'),wait(2000)]);
  }
}
async function request(token,method,path,action) {
  const r=await fetch(CLOUD+path,{
    method,redirect:'manual',signal:AbortSignal.timeout(9000),
    headers:{
      ...(token?{Authorization:'Bearer '+token}:{}),
      ...(action?{'X-PhiCloud-Action':action}:{}),
    },
  });
  return r;
}
const url=(team,tail='records')=>'/v1/private/tenants/'+team+'/'+tail;
const check=async(r,status,label)=>assert.equal(r.status,status,label);
async function runTests(adminToken,alice,bob,secret){
  const temp=mkdtempSync(join(tmpdir(),'phicloud-r6-e2e-'));
  const independent=mkdtempSync(join(tmpdir(),'phicloud-r9-witness-'));
  const path=join(temp,'private.sqlite');
  const fence=join(independent,'owner-revocations.jsonl');
  const snapshot=join(temp,'older-snapshot.sqlite');
  let aliceRead,aliceWrite,bobRead,bobWrite;
  try{
    aliceRead=await login(alice,READ);
    aliceWrite=await login(alice,WRITE);
    bobRead=await login(bob,READ);
    bobWrite=await login(bob,WRITE);
    const provision=tenantFixture(alice,bob);
    let aliceId,bobId,betaId;
    console.log('R6: checking exact scopes and two distinct verified owners');
    await withPython(path,secret,provision,async()=>{
      await check(await request(null,'GET',url('alpha-team')),401,'anonymous read');
      await check(await request(aliceWrite,'GET',url('alpha-team')),401,'write-only cannot read');
      await check(await request(aliceRead,'POST',url('alpha-team'),
        'create-tenant-test-record'),401,'read-only cannot create');
      await check(await request(aliceWrite,'POST',url('alpha-team')),403,'explicit action required');
      await check(await request(aliceRead,'GET',url('beta-team')),404,'unassigned tenant');

      let r=await request(aliceWrite,'POST',url('alpha-team'),'create-tenant-test-record');
      await check(r,201,'Alice creates only own record');aliceId=(await r.json()).id;
      r=await request(bobWrite,'POST',url('alpha-team'),'create-tenant-test-record');
      await check(r,201,'Bob creates only own record');bobId=(await r.json()).id;
      r=await request(bobWrite,'POST',url('beta-team'),'create-tenant-test-record');
      await check(r,201,'Bob creates record in separately provisioned tenant');
      betaId=(await r.json()).id;
      assert.notEqual(aliceId,bobId);

      await check(await request(aliceRead,'GET',url('alpha-team','records/'+aliceId)),200);
      await check(await request(bobRead,'GET',url('alpha-team','records/'+bobId)),200);
      await check(await request(bobRead,'GET',url('alpha-team','records/'+aliceId)),404,
        'Bob cannot read Alice record despite tenant membership');
      await check(await request(aliceRead,'GET',url('alpha-team','records/'+bobId)),404,
        'Alice cannot read Bob record');
      await check(await request(bobWrite,'DELETE',url('alpha-team','records/'+aliceId),
        'delete-tenant-test-record'),404,'Bob cannot delete Alice record');
      await check(await request(aliceRead,'GET',url('beta-team','records/'+betaId)),404);
      const a=await(await request(aliceRead,'GET',url('alpha-team'))).json();
      const b=await(await request(bobRead,'GET',url('alpha-team'))).json();
      assert.deepEqual(a.records.map(x=>x.id),[aliceId]);
      assert.deepEqual(b.records.map(x=>x.id),[bobId]);
      const aAudit=await(await request(aliceRead,'GET',url('alpha-team','audit'))).json();
      assert.deepEqual(aAudit.events.map(x=>x.record_id),[aliceId]);
    });
    console.log('R6: restarting resource server and reopening private SQLite');
    await withPython(path,secret,null,async()=>{
      await check(await request(aliceRead,'GET',url('alpha-team','records/'+aliceId)),200,
        'Alice private durable record survives restart');
      await check(await request(bobRead,'GET',url('alpha-team','records/'+bobId)),200,
        'Bob private durable record survives restart');
      await check(await request(bobRead,'GET',url('alpha-team','records/'+aliceId)),404,
        'restart must not break isolation');
      const aAudit=await(await request(aliceRead,'GET',url('alpha-team','audit'))).json();
      assert.deepEqual(aAudit.events.map(x=>x.record_id),[aliceId]);

      await check(await request(aliceWrite,'DELETE',url('alpha-team','records/'+aliceId),
        'delete-tenant-test-record'),200);
      await check(await request(aliceRead,'GET',url('alpha-team','records/'+aliceId)),404);
      const audit=await(await request(aliceRead,'GET',url('alpha-team','audit'))).json();
      assert.deepEqual(audit.events.map(x=>x.action),['delete','create']);

      console.log('R6: revoking only Alice Keycloak sessions');
      const loggedOut=await admin(adminToken,'users/'+alice.userId+'/logout',{method:'POST'});
      assert.equal(loggedOut.status,204);
      await check(await request(aliceRead,'GET',url('alpha-team')),401,
        'revoked Alice token must be denied');
      await check(await request(bobRead,'GET',url('alpha-team','records/'+bobId)),200,
        'Bob token must remain active after Alice logout');
      await check(await request(bobRead,'GET',url('beta-team','records/'+betaId)),200,
        'Bob separate tenant record unaffected');
    });
    console.log('R6: verifying durable delete and owner-isolated audit after another restart');
    await withPython(path,secret,null,async()=>{
      const a=await(await request(bobRead,'GET',url('alpha-team'))).json();
      assert.deepEqual(a.records.map(x=>x.id),[bobId]);
      const b=await(await request(bobRead,'GET',url('beta-team'))).json();
      assert.deepEqual(b.records.map(x=>x.id),[betaId]);
      await check(await request(bobWrite,'DELETE',url('alpha-team','records/'+bobId),
        'delete-tenant-test-record'),200);
      await check(await request(bobRead,'GET',url('alpha-team','records/'+bobId)),404);
    });
    console.log('R8: offline operator removal, no leaked subject in argv or output');
    const operatorInput=JSON.stringify({
      schema:'phicloud.local-tenant-operator-request.v0.1',
      tenant:'alpha-team',
      member:{iss:ISSUER,sub:bob.userId},
      acknowledge:'REVOKE alpha-team',
    });
    const cmd=['-m','phicloud.tenant_operator','--db',path,'--apply'];
    const operatorEnv={
      ...process.env,
      PHICLOUD_TENANT_OPERATOR_DEV:'1',
      PHICLOUD_ENV:'test',
      NODE_ENV:'test',
    };
    const removed=spawnSync('python',cmd,{
      input:operatorInput,encoding:'utf8',
      env:operatorEnv,timeout:9000,
    });
    assert.equal(removed.status,0,'offline operator must revoke verified local member');
    const result=JSON.parse(removed.stdout);
    assert.equal(result.schema,'phicloud.local-tenant-operator-result.v0.1');
    assert.equal(result.changed,true);
    assert.equal(result.external_token_revoked,false);
    assert.equal(result.tenant,'alpha-team');
    assert.equal(result.removed_markers,0,'Alice deleted and Bob deleted their own alpha markers');
    assert.ok(!removed.stdout.includes(bob.userId));
    assert.ok(!removed.stdout.includes(ISSUER));
    const again=spawnSync('python',cmd,{
      input:operatorInput,encoding:'utf8',
      env:operatorEnv,timeout:9000,
    });
    assert.equal(again.status,0);
    assert.equal(JSON.parse(again.stdout).changed,false);

    console.log('R8: still-active Keycloak bearer cannot resurrect removed tenant membership');
    await withPython(path,secret,null,async()=>{
      await check(await request(bobRead,'GET',url('alpha-team')),404,
        'valid bearer no longer grants removed tenant membership');
      await check(await request(bobWrite,'POST',url('alpha-team'),
        'create-tenant-test-record'),404,
        'valid write scope does not regrant membership');
      await check(await request(bobRead,'GET',url('beta-team','records/'+betaId)),200,
        'unrelated tenant membership must remain usable');
    });
    console.log('R9: enrolling independent private witness with existing R8 tombstone');
    const recoveryCmd=(mode)=>[
      '-m','phicloud.tenant_recovery','--db',path,'--witness',fence,'--'+mode
    ];
    const recoveryEnv={
      ...process.env, PHICLOUD_TENANT_RECOVERY_DEV:'1',
      PHICLOUD_ENV:'test',NODE_ENV:'test',
    };
    const runRecovery=(mode,confirmation)=>spawnSync('python',recoveryCmd(mode),{
      input:JSON.stringify({
        schema:'phicloud.tenant-recovery-operator/0.1',
        confirmation,
      }),
      encoding:'utf8',env:recoveryEnv,timeout:9000,
    });
    const enrolled=runRecovery('enroll','ENROLL INDEPENDENT WITNESS');
    assert.equal(enrolled.status,0,'offline witness enrollment must succeed');
    assert.equal(JSON.parse(enrolled.stdout).existing_revocations,1);
    assert.ok(!enrolled.stdout.includes(bob.userId));
    copyFileSync(path,snapshot);

    console.log('R9: append second revocation to independent witness');
    const revokeBeta=JSON.stringify({
      schema:'phicloud.local-tenant-operator-request.v0.1',
      tenant:'beta-team',
      member:{iss:ISSUER,sub:bob.userId},
      acknowledge:'REVOKE beta-team',
    });
    const guardedOperator=spawnSync('python',[
      '-m','phicloud.tenant_operator','--db',path,'--apply'
    ],{
      input:revokeBeta,encoding:'utf8',timeout:9000,
      env:{
        ...operatorEnv,PHICLOUD_ENABLE_FENCE_DEV:'1',
        PHICLOUD_TENANT_FENCE_PATH:fence,
      }
    });
    assert.equal(guardedOperator.status,0,'witnessed operator revoke failed');
    assert.equal(JSON.parse(guardedOperator.stdout).removed_markers,1);

    console.log('R9: restoring stale SQLite snapshot WITHOUT rewinding separate witness');
    copyFileSync(snapshot,path);
    const startup=spawnSync('python',[
      '-c', 'import sys; from phicloud.tenant_store import LocalTenantStore; '+
      'LocalTenantStore(sys.argv[1],fence_path=sys.argv[2])',
      path,fence
    ],{encoding:'utf8',timeout:7000});
    assert.notEqual(startup.status,0,'stale SQLite snapshot unexpectedly accepted');

    console.log('R9: offline revoke-only reconciliation and post-recovery denial');
    const repaired=runRecovery('reconcile','RECONCILE REVOKE ONLY');
    assert.equal(repaired.status,0,'safe recovery must reapply independent revocation');
    const recovered=JSON.parse(repaired.stdout);
    assert.equal(recovered.reconciled_revocations,1);
    assert.equal(recovered.access_regranted,false);
    await withPython(path,secret,null,async()=>{
      await check(await request(bobRead,'GET',url('beta-team')),404,
        'still-valid Keycloak bearer was able to use restored beta membership');
      await check(await request(bobWrite,'POST',url('beta-team'),
        'create-tenant-test-record'),404,
        'still-valid Keycloak write token regranted beta membership');
      await check(await request(bobRead,'GET',url('alpha-team')),404,
        'earlier alpha-team revoke must also remain effective');
    },fence);
    console.log('PASS: R9 stale backup rejected; independent witness reapplies revoked membership, no real data');

    console.log('PASS: R8 offline operator revocation survives restart, denies still-active scoped token, preserves other tenant');
    console.log('PASS: real Keycloak two-subject tenant membership, owner isolation, scoped operations, durable deletes/audit, restart and independent revocation');
    console.log('BOUNDARY: no PhiVault files, user-supplied content, hosted storage, email or PhiOS actions');
  }finally{
    rmSync(temp,{recursive:true,force:true});
    rmSync(independent,{recursive:true,force:true});
  }
}

async function main(){
  console.log('R6: waiting for disposable Keycloak');
  await fixture.waitForKeycloak();
  const adminToken=await fixture.adminToken();
  let alice,bob;
  try {
    const secret=await createConfidentialResource(adminToken);
    await configureScope(adminToken,READ);
    await configureScope(adminToken,WRITE);
    alice=await fixture.createDisposableUser(adminToken);
    bob=await fixture.createDisposableUser(adminToken);
    await runTests(adminToken,alice,bob,secret);
  }finally{
    for(const user of [bob,alice]){
      if(user?.userId){
        const removed=await admin(adminToken,'users/'+user.userId,{method:'DELETE'});
        assert.equal(removed.status,204,'disposable test account cleanup');
      }
    }
  }
}

const keepAlive=setInterval(()=>{},1000);
try {await main();}
catch(error){
  // No tokens, callback URLs, session cookies, admin passwords or raw IdP
  // error bodies are ever printed by this integration test.
  console.error('R6 real Keycloak tenant test failed:',
    error?.name==='AssertionError'?'test_contract_failure':'local_fixture_failure');
  process.exitCode=1;
}finally{clearInterval(keepAlive);}
