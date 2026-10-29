const assert = require('node:assert/strict');
const express = require('express');
const { probeEmptyStateAuthz, probeClientTrustedRole } = require('../cases/03-blind-probe/probe');
const { renderDecisionExplicit } = require('../cases/01-empty-200-as-disabled/frontend');
let checks=0;
function check(name, fn) { fn(); checks++; console.log(`PASS ${name}`); }
async function withServer(factory, fn) {
 const {app,state}=factory(); const server=app.listen(0,'127.0.0.1');
 await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject)});
 try {await fn(`http://127.0.0.1:${server.address().port}`,state)} finally {await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))}
}
async function call(base,path,token,body) {
 const response=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(3000)});
 return {status:response.status,body:await response.json().catch(()=>null)};
}
async function login(base,u,p) {const r=await call(base,'/login',null,{username:u,password:p});assert.equal(r.status,200);assert.equal(typeof r.body.token,'string');return r.body.token}
async function run() {
 for (const id of ['01-empty-200-as-disabled','04-ssr-state-exposure']) for(const variant of ['vulnerable','fixed']) {
  await withServer(require(`../cases/${id}/${variant}/server`).createApp,async(base,state)=>{
   const disabled=await login(base,'disabled','pw-dis-1');
   const active=id.startsWith('01')?await login(base,'active_empty','pw-empty-1'):await login(base,'active','pw-act-1');
   const allowed=await call(base,'/api/restricted-brief',active);
   check(`${id}/${variant}: active control retrieves protected fixture`,()=>assert.equal(allowed.body.brief,'FIXTURE-RESTRICTED-BRIEF'));
   const locked=await call(base,'/api/restricted-brief',disabled);
   check(`${id}/${variant}: disabled session resource boundary`,()=>{assert.equal(locked.status,variant==='fixed'?403:200);if(variant==='fixed')assert.equal(locked.body.brief,undefined);else assert.equal(locked.body.brief,'FIXTURE-RESTRICTED-BRIEF')});
   const anonymous=await call(base,'/api/restricted-brief');
   check(`${id}/${variant}: missing session denied`,()=>assert.equal(anonymous.status,401));
   const forged=await call(base,'/api/restricted-brief','constructor');
   check(`${id}/${variant}: inherited-property token denied`,()=>assert.equal(forged.status,401));
   // Revoke after login: authorization is recomputed on each request.
   const user=Object.values(state.users).find(u=>u.id===allowed.body.owner);user.status='disabled';
   const revoked=await call(base,'/api/restricted-brief',active);
   check(`${id}/${variant}: live status revocation`,()=>assert.equal(revoked.status,variant==='fixed'?403:200));
  });
 }
 check('Changing entire response can still redraw a fixed client; no UI integrity claim',()=>assert.equal(renderDecisionExplicit(200,{projects:[{id:'fake'}]}),'DASHBOARD'));
 for(const variant of ['vulnerable','fixed']) await withServer(require(`../cases/05-idor-cross-user/${variant}/server`).createApp,async base=>{
  const a=await login(base,'alice','pw-alice-1'),b=await login(base,'bob','pw-bob-1');
  const own=await call(base,'/api/profile/prof_bob_1077',b);
  check(`IDOR/${variant}: second owner positive control`,()=>assert.equal(own.body.email,'bob@example.test'));
  const missing=await call(base,'/api/profile/constructor',a);
  check(`IDOR/${variant}: inherited key is not a profile`,()=>assert.equal(missing.status,404));
  const unknown=await call(base,'/api/profile/does-not-exist',a);
  check(`IDOR/${variant}: unknown record`,()=>assert.equal(unknown.status,404));
  const noauth=await call(base,'/api/profile/prof_bob_1077');
  check(`IDOR/${variant}: anonymous denied`,()=>assert.equal(noauth.status,401));
 });
 const creds={activeEmpty:{u:'active_empty',p:'pw-empty-1'},disabled:{u:'disabled',p:'pw-dis-1'}};
 const roleCreds={lowPriv:{u:'student',p:'pw-stu-1'},elevatedRole:'fellow'};
 for(const kind of ['login-error','server-error','malformed-json','different-empty','login-redirect']) {
  await withServer(()=>{const app=express();app.use(express.json());app.post('/login',(req,res)=>kind==='login-error'?res.status(401).json({}):kind==='login-redirect'?res.redirect('/elsewhere'):res.json({token:req.body.username}));app.use((req,res)=>{if(kind==='malformed-json')return res.type('json').send('{');if(kind==='different-empty')return res.json({projects:[],unrelated:true});res.status(503).json({error:'unavailable'})});return{app}},async base=>{
   const empty=await probeEmptyStateAuthz(base,creds),role=await probeClientTrustedRole(base,roleCreds);
   check(`${kind}: empty-state probe inconclusive`,()=>assert.equal(empty.verdict,'INCONCLUSIVE'));
   check(`${kind}: role probe inconclusive`,()=>assert.equal(role.verdict,'INCONCLUSIVE'));
  });
 }
 console.log(`BOUNDARY_CHECKS ${checks} passed`);
}
run().catch(error=>{console.error(error);process.exitCode=1});
