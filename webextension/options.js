// Options page: grants or revokes the optional permissions that let the
// background script answer HTTP authentication challenges. It holds no
// secrets and talks to neither the page nor the native host.

const toggleEl = document.getElementById("toggle");
const stateEl = document.getElementById("state");

// Whether the permissions are currently granted; kept in step with the button.
let enabled = false;

function render(granted) {
  enabled = granted;
  toggleEl.textContent = granted ? "Turn off" : "Turn on";
  toggleEl.disabled = false;
  stateEl.textContent = granted ? "On" : "Off";
  stateEl.className = granted ? "on" : "muted";
}

function showError(text) {
  stateEl.textContent = text;
  stateEl.className = "error";
}

// `permissions.request()` must run inside the user-input handler, so it is the
// first thing this does — nothing may be awaited before it.
toggleEl.addEventListener("click", () => {
  const enabling = !enabled;
  toggleEl.disabled = true;
  const action = enabling
    ? browser.permissions.request(AUTH_PERMISSIONS)
    : browser.permissions.remove(AUTH_PERMISSIONS);
  action
    .then(async (ok) => {
      await init(); // report what the browser actually granted, not what we asked for
      if (enabling && !ok) showError("Permission declined.");
    })
    .catch((e) => {
      toggleEl.disabled = false;
      showError("Error: " + e.message);
    });
});

// Reflect changes made elsewhere (about:addons → Permissions).
browser.permissions.onAdded.addListener(init);
browser.permissions.onRemoved.addListener(init);

async function init() {
  render(await browser.permissions.contains(AUTH_PERMISSIONS));
}

init();
