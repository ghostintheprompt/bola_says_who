// Two client hydration models.
//
// hydrateFromFlag (vulnerable client): reads the initial-state <script> blob
// the server embedded and decides what to mount from the isActive flag inside
// it. The decision lives in a value shipped to — and therefore editable by —
// the browser. This is what makes state injection work.
//
// hydrateFromServerView (fixed client): mounts whatever authoritative view the
// server actually rendered into #root, with no client-side authorization flag
// to read or flip.

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
