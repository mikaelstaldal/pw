// Background script for the pw Firefox extension.
//
// Holds the native-messaging port to `pw-browser-host` and drives the fill
// flow. Contains no crypto and stores no secrets at rest: credentials live in
// function/Map scope only for as long as a fill is in flight, and nothing is
// written to browser.storage, the clipboard, or the DOM by this script.

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

browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.cmd === "fill-request") return fillFlow();
  if (msg && msg.cmd === "pick") return pick(msg.tabId, msg.name);
  if (msg && msg.cmd === "lock") return send({ type: "lock" }).catch((e) => ({ error: e.message }));
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
