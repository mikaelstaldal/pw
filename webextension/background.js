// Background script for the pw Firefox extension.
//
// Holds the native-messaging port to `pw-browser-host` and drives the fill
// flow, plus — when the user has granted the optional permissions for it — the
// HTTP-authentication flow at the bottom of this file. Contains no crypto and
// stores no secrets at rest: credentials live in function/Map scope only for as
// long as a fill is in flight, and nothing is written to browser.storage, the
// clipboard, or the DOM by this script.

const HOST = "nu.staldal.pw";

// One long-lived port per background script so the host process — and its
// in-memory unlock cache — survives across fills (§4.1, §4.3). A fresh port
// per request would spawn a new host and re-prompt every time.
let port = null;
let nextId = 1;
const pending = new Map(); // request id -> {resolve, reject}

// Per-tab matching entries (passwords included) waiting for the user to pick
// one in the popup. Held only between a multi-match query and the pick/close.
const pendingByTab = new Map();

function ensurePort() {
  if (port) return port;
  port = browser.runtime.connectNative(HOST);
  port.onMessage.addListener((msg) => {
    const waiter = pending.get(msg.id);
    if (waiter) {
      pending.delete(msg.id);
      waiter.resolve(msg);
    }
  });
  port.onDisconnect.addListener((p) => {
    const error =
      (p.error && p.error.message) ||
      (browser.runtime.lastError && browser.runtime.lastError.message) ||
      "native host disconnected";
    port = null;
    for (const [, waiter] of pending) waiter.reject(new Error(error));
    pending.clear();
  });
  return port;
}

// Send a request and resolve with the matching response (matched by id).
function send(message) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    try {
      ensurePort().postMessage(Object.assign({ id }, message));
    } catch (e) {
      pending.delete(id);
      reject(e);
    }
  });
}

function originForTab(tab) {
  try {
    // The origin is taken from the tab's own URL, never from anything the
    // page reports (§5.1 step 2, §9).
    return new URL(tab.url).origin;
  } catch (e) {
    return null;
  }
}

async function activeTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function errorMessage(resp) {
  switch (resp.code) {
    case "invalid-origin":
      return "This page is not an https login page.";
    case "no-match":
      return "No matching login in your vault.";
    case "unlock-cancelled":
      return "Unlock cancelled.";
    case "scrypt-failed":
      return "Could not unlock the vault (wrong passphrase?).";
    case "db-missing":
      return "No vault file found.";
    default:
      return resp.message || "The pw host reported an error.";
  }
}

// Inject the fill script (top-level frame only) and hand it the credential.
// The credential exists only as arguments here and is dropped when this
// function returns (§5.1 step 6).
async function fillTab(tabId, entry) {
  await browser.tabs.executeScript(tabId, { file: "/fill.js" });
  const result = await browser.tabs.sendMessage(tabId, {
    type: "pw-fill",
    username: entry.username,
    password: entry.password,
  });
  setBadge(tabId, result && result.filledPassword);
  return result;
}

function setBadge(tabId, ok) {
  if (typeof tabId !== "number" || tabId < 0) return; // not tied to a tab
  const text = ok ? "✓" : "!";
  const color = ok ? "#2e7d32" : "#c62828";
  browser.browserAction.setBadgeText({ tabId, text });
  browser.browserAction.setBadgeBackgroundColor({ tabId, color });
  setTimeout(() => browser.browserAction.setBadgeText({ tabId, text: "" }), 3000);
}

// The core flow, returning a plain object the popup can render. Passwords are
// never put in the returned object — only name/username for the chooser.
async function fillFlow() {
  const tab = await activeTab();
  if (!tab) return { error: "No active tab." };
  const origin = originForTab(tab);
  if (!origin) return { error: "This page has no fillable origin." };

  let resp;
  try {
    resp = await send({ type: "get-logins", origin });
  } catch (e) {
    return { error: "Cannot reach the pw host: " + e.message };
  }
  if (resp.type === "error") {
    return { error: errorMessage(resp), code: resp.code };
  }

  const entries = resp.entries || [];
  if (entries.length === 0) return { error: "No matching login." };
  if (entries.length === 1) {
    const result = await fillTab(tab.id, entries[0]);
    return { filled: result, name: entries[0].name };
  }

  // More than one match: keep them for the popup to choose from.
  pendingByTab.set(tab.id, entries);
  return {
    choices: entries.map((e) => ({ name: e.name, username: e.username })),
  };
}

async function pick(tabId, name) {
  const entries = pendingByTab.get(tabId);
  pendingByTab.delete(tabId);
  if (!entries) return { error: "Selection expired; try again." };
  const entry = entries.find((e) => e.name === name);
  if (!entry) return { error: "Selection not found." };
  const result = await fillTab(tabId, entry);
  return { filled: result, name: entry.name };
}

// Is the vault unlocked? `status` never prompts, so this is free to call.
async function vaultStatus() {
  let resp;
  try {
    resp = await send({ type: "status" });
  } catch (e) {
    return { error: "Cannot reach the pw host: " + e.message };
  }
  if (!resp || resp.type !== "status") return { error: "Unexpected reply from the pw host." };
  return { locked: resp.locked };
}

// Unlock ahead of any fill, so the passphrase is entered when the user chooses
// rather than when a fill needs it. The host prompts in pinentry, outside the
// browser, and releases no entry — this cannot return a credential.
async function unlockVault() {
  let resp;
  try {
    resp = await send({ type: "unlock" });
  } catch (e) {
    return { error: "Cannot reach the pw host: " + e.message };
  }
  if (resp.type === "error") return { error: errorMessage(resp), code: resp.code };
  if (resp.type !== "status") return { error: "Unexpected reply from the pw host." };
  // Still locked after a successful unlock means the host is configured not to
  // cache (`cache_minutes: 0`), so there was nothing to keep.
  return { locked: resp.locked };
}

async function lockVault() {
  let resp;
  try {
    resp = await send({ type: "lock" });
  } catch (e) {
    return { error: "Cannot reach the pw host: " + e.message };
  }
  if (!resp || resp.type !== "ok") return { error: "Unexpected reply from the pw host." };
  return { locked: true };
}

browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.cmd === "fill-request") return fillFlow();
  if (msg && msg.cmd === "pick") return pick(msg.tabId, msg.name);
  if (msg && msg.cmd === "status") return vaultStatus();
  if (msg && msg.cmd === "unlock") return unlockVault();
  if (msg && msg.cmd === "lock") return lockVault();
  return false;
});

// Context-menu entry routes through the same popup so multi-match selection
// has somewhere to render.
browser.menus.create({
  id: "pw-fill",
  title: "Fill login with pw",
  contexts: ["page", "editable"],
});
browser.menus.onClicked.addListener((info) => {
  if (info.menuItemId === "pw-fill") {
    browser.browserAction.openPopup().catch(() => {});
  }
});

// --- HTTP authentication (opt-in) ------------------------------------------
//
// Firefox's HTTP-auth prompt is browser chrome, not DOM, so it cannot be
// filled. Instead, with the optional permissions in `auth-permissions.js`
// granted, the 401 is answered before the prompt is shown and the prompt never
// appears. Declining to answer (returning `{}`) always falls back to it.
//
// Unlike the form fill, this has no user gesture behind it, so it is
// deliberately narrow: top-level document loads only (never a subresource or
// an iframe, so an embedded `<img>`/`<iframe>` cannot make the browser submit
// your credentials somewhere in the background), never a proxy challenge,
// never while the vault is locked — a page must not be able to summon a
// pinentry dialog — and only for an entry whose site is *exactly* the
// challenging host, so a subdomain someone else controls cannot silently
// collect the parent domain's password.

// Requests we have already answered once. A second challenge for the same id
// means the credentials were refused, and the user gets the native dialog.
const answeredAuth = new Set();

// The host is local and already unlocked on this path, so a round-trip is
// quick; if it is not, let the request proceed to the dialog rather than
// stalling the page load.
const AUTH_TIMEOUT_MS = 5000;

function withTimeout(promise) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(null), AUTH_TIMEOUT_MS)),
  ]);
}

// Ask the host for the one entry whose site is exactly this host.
//
// `get-logins-strict` is a different request from the one the form fill uses:
// it matches the host exactly rather than accepting a parent domain, and it
// answers a locked vault with an error instead of prompting. Both guarantees
// therefore hold inside the host, on the same request that returns the
// credential — not as a separate check here that the vault could expire
// behind. A host too old to know the request type answers `error/internal`,
// which declines here rather than quietly falling back to looser matching.
async function lookupAuth(origin) {
  let resp;
  try {
    resp = await send({ type: "get-logins-strict", origin });
  } catch (e) {
    return null;
  }
  if (!resp || resp.type !== "logins") return null;
  const entries = resp.entries || [];
  // With several matches there is nowhere to ask which one — the popup cannot
  // be opened without a user gesture — so defer to the native dialog.
  if (entries.length !== 1) return null;
  return entries[0];
}

async function provideCredentials(details) {
  if (details.isProxy) return {};
  if (details.type !== "main_frame") return {};
  if (answeredAuth.has(details.requestId)) {
    answeredAuth.delete(details.requestId);
    return {}; // refused — hand the challenge to Firefox's own dialog
  }

  let url;
  try {
    url = new URL(details.url);
  } catch (e) {
    return {};
  }
  // The scheme comes from the request URL (so the host's https-only rule
  // applies), the host from the challenger; they must agree.
  const challenger = details.challenger && details.challenger.host;
  if (!challenger || url.hostname.toLowerCase() !== challenger.toLowerCase()) {
    return {};
  }

  const entry = await withTimeout(lookupAuth(url.origin));
  if (!entry) return {};

  answeredAuth.add(details.requestId);
  return {
    authCredentials: { username: entry.username, password: entry.password },
  };
}

// Tabs where we answered the challenge of the load now in flight. The badge
// cannot be set at that moment: a tab's badge is reset when the tab navigates,
// and this navigation is the one still going. It is set when the page is done
// loading instead.
const authFilledTabs = new Set();

function authCompleted(details) {
  if (!answeredAuth.delete(details.requestId)) return;
  // A 401 here means our credentials were refused and the user dealt with the
  // dialog themselves; only a request that went through was our doing.
  if (details.statusCode !== 401 && details.tabId >= 0) {
    authFilledTabs.add(details.tabId);
  }
}

function authFailed(details) {
  answeredAuth.delete(details.requestId);
}

// An HTTP-auth fill is otherwise completely invisible — no dialog, no form
// that visibly changes — so the badge is the only sign it happened.
function badgeAuthFill(tabId, changeInfo) {
  if (changeInfo.status !== "complete") return;
  if (authFilledTabs.delete(tabId)) setBadge(tabId, true);
}

function forgetAuthTab(tabId) {
  authFilledTabs.delete(tabId);
}

// Registration follows the permission, so revoking it in the options page (or
// in about:addons) takes effect at once, with no restart.
function syncAuthListeners(granted) {
  if (!granted) {
    // Before the API check below: the namespace disappears with the
    // permission, and this state must be dropped either way.
    answeredAuth.clear();
    authFilledTabs.clear();
  }
  if (!browser.webRequest) return; // API absent until the permission is granted
  const registered = browser.webRequest.onAuthRequired.hasListener(provideCredentials);
  if (granted && !registered) {
    const filter = { urls: AUTH_PERMISSIONS.origins };
    browser.webRequest.onAuthRequired.addListener(provideCredentials, filter, ["blocking"]);
    browser.webRequest.onCompleted.addListener(authCompleted, filter);
    browser.webRequest.onErrorOccurred.addListener(authFailed, filter);
    browser.tabs.onUpdated.addListener(badgeAuthFill, { properties: ["status"] });
    browser.tabs.onRemoved.addListener(forgetAuthTab);
  } else if (!granted && registered) {
    browser.webRequest.onAuthRequired.removeListener(provideCredentials);
    browser.webRequest.onCompleted.removeListener(authCompleted);
    browser.webRequest.onErrorOccurred.removeListener(authFailed);
    browser.tabs.onUpdated.removeListener(badgeAuthFill);
    browser.tabs.onRemoved.removeListener(forgetAuthTab);
  }
}

async function refreshAuthListeners(attempt) {
  const granted = await browser.permissions.contains(AUTH_PERMISSIONS);
  // The webRequest namespace only exists while the permission is held; on a
  // fresh grant it can appear a moment after the event, so retry briefly
  // rather than leaving the feature dead until the next browser start.
  if (granted && !browser.webRequest) {
    if (attempt < 5) setTimeout(() => refreshAuthListeners(attempt + 1), 200);
    return;
  }
  syncAuthListeners(granted);
}

browser.permissions.onAdded.addListener(() => refreshAuthListeners(0));
browser.permissions.onRemoved.addListener(() => refreshAuthListeners(0));
refreshAuthListeners(0);
