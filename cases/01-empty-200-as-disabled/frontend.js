// A faithful, minimal model of the vulnerable client's decision logic, as
// observed in the field: the client has no explicit authorization signal to
// read, so it decides what to render purely from whether the projects list
// came back non-empty.
//
//   non-empty list -> mount the dashboard
//   empty list     -> render the "account disabled" screen
//
// This is the exact logic that makes response injection work: the client is
// the only thing deciding, and it decides on data presence alone.
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
