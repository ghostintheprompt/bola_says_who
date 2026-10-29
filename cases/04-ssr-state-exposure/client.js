// Pure hydration models, not a browser runtime or an authorization control.
function readStateBlob(html) {
  const m = html.match(/<script id="__APP_STATE__" type="application\/json">([\s\S]*?)<\/script>/);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

function hydrateFromFlag(html) {
  const state = readStateBlob(html);
  if (!state) return 'NO_STATE';
  return state.isActive ? 'DASHBOARD' : 'ACCOUNT_DISABLED';
}

function hydrateFromServerView(html) {
  const m = html.match(/data-view="([^"]+)"/);
  const view = m && m[1];
  if (view === 'dashboard') return 'DASHBOARD';
  if (view === 'account-disabled') return 'ACCOUNT_DISABLED';
  return 'NO_VIEW';
}

module.exports = { readStateBlob, hydrateFromFlag, hydrateFromServerView };
