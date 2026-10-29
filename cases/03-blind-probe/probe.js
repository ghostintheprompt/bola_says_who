// Behavioral classifiers for these local fixture contracts, not general scanners.
async function request(base, path, options = {}) {
  try {
    const response = await fetch(new URL(path, base), { ...options, redirect: 'error', signal: AbortSignal.timeout(3000) });
    const body = await response.json();
    return { status: response.status, body };
  } catch (error) { return { error: error.name }; }
}
async function login(base, credentials) {
  const result = await request(base, '/login', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({username:credentials.u,password:credentials.p})});
  return result.status === 200 && typeof result.body?.token === 'string' && result.body.token ? result.body.token : null;
}
function auth(token) { return { authorization: `Bearer ${token}` }; }
async function probeEmptyStateAuthz(base, creds) {
  const active = await login(base, creds.activeEmpty), disabled = await login(base, creds.disabled);
  if (!active || !disabled) return { verdict:'INCONCLUSIVE', evidence:{reason:'fixture login failed'} };
  const empty = await request(base, '/api/projects', {headers:auth(active)});
  const locked = await request(base, '/api/projects', {headers:auth(disabled)});
  const brief = await request(base, '/api/restricted-brief', {headers:auth(disabled)});
  const control = await request(base, '/api/restricted-brief', {headers:auth(active)});
  const validControl = empty.status === 200 && Array.isArray(empty.body?.projects) && empty.body.projects.length === 0 && control.status === 200 && control.body?.brief === 'FIXTURE-RESTRICTED-BRIEF';
  let verdict='INCONCLUSIVE';
  if (validControl && locked.status === 200 && JSON.stringify(locked.body) === JSON.stringify(empty.body) && brief.status === 200 && brief.body?.brief === 'FIXTURE-RESTRICTED-BRIEF') verdict='VULNERABLE';
  if (validControl && locked.status === 403 && locked.body?.code === 'ACCOUNT_DISABLED' && brief.status === 403 && brief.body?.code === 'ACCOUNT_DISABLED' && !('brief' in brief.body)) verdict='SOUND';
  return {verdict,evidence:{empty,disabled:locked,brief,control}};
}
async function probeClientTrustedRole(base, creds) {
  const token = await login(base, creds.lowPriv);
  if (!token) return {verdict:'INCONCLUSIVE',evidence:{reason:'fixture login failed'}};
  const baseline=await request(base,'/api/dashboard',{headers:auth(token)});
  const escalated=await request(base,'/api/dashboard',{headers:{...auth(token),'x-role':creds.elevatedRole}});
  let verdict='INCONCLUSIVE';
  if (baseline.status === 200 && baseline.body?.role === 'student' && Array.isArray(baseline.body.payouts) && baseline.body.payouts.length === 0) {
    if (escalated.status === 200 && escalated.body?.role === creds.elevatedRole && Array.isArray(escalated.body.payouts) && escalated.body.payouts.length > 0) verdict='VULNERABLE';
    if (escalated.status === 200 && escalated.body?.role === 'student' && Array.isArray(escalated.body.payouts) && escalated.body.payouts.length === 0) verdict='SOUND';
  }
  return {verdict,evidence:{baseline,escalated}};
}
module.exports={probeEmptyStateAuthz,probeClientTrustedRole};
