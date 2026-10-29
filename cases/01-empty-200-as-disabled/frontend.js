// Pure rendering models. A changed screen is not a server authorization receipt.
function renderDecision(httpStatus, body) {
  // The vulnerable client ignores status nuance and keys off the payload.
  const projects = (body && body.projects) || [];
  if (projects.length > 0) return 'DASHBOARD';
  return 'ACCOUNT_DISABLED';
}

// A client that keys off an explicit authorization decision instead. It
// renders the disabled screen only when the server actually says the account
// is not permitted, and treats an empty-but-authorized response as an empty
// dashboard, not a lockout. Injecting projects into a 403 body changes nothing.
function renderDecisionExplicit(httpStatus, body) {
  if (httpStatus === 403 && body && body.code === 'ACCOUNT_DISABLED') {
    return 'ACCOUNT_DISABLED';
  }
  if (httpStatus === 200) return 'DASHBOARD'; // empty list is still the dashboard
  return 'ERROR';
}

module.exports = { renderDecision, renderDecisionExplicit };
