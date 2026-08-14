// Popup UI. Asks the background script to
// run the fill flow and, when more than one entry matches, lets the user pick.
// It never sees passwords — only names and usernames — and stores nothing.

const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");

function showStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.classList.toggle("error", !!isError);
}

function describeFill(result) {
  if (!result.filled) return "Done.";
  if (!result.filled.filledPassword) {
    return "No login form found on this page.";
  }
  return result.filled.filledUsername
    ? "Filled username and password."
    : "Filled password (no username field found).";
}

function clearList() {
  while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
}

async function choose(name) {
  showStatus("Filling…");
  clearList();
  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  const result = await browser.runtime.sendMessage({
    cmd: "pick",
    tabId: tab.id,
    name,
  });
  if (!result || result.error) {
    showStatus(result ? result.error : "No response.", true);
    return;
  }
  showStatus(describeFill(result), result.filled && !result.filled.filledPassword);
  setTimeout(() => window.close(), 900);
}

function renderChoices(choices) {
  for (const choice of choices) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = choice.name;
    button.appendChild(name);
    if (choice.username) {
      const user = document.createElement("span");
      user.className = "user";
      user.textContent = " — " + choice.username;
      button.appendChild(user);
    }
    button.addEventListener("click", () => choose(choice.name));
    li.appendChild(button);
    listEl.appendChild(li);
  }
}

document.getElementById("settings").addEventListener("click", () => {
  browser.runtime.openOptionsPage();
  window.close();
});

// Unlock/lock the vault without filling anything. Unlocking here is what makes
// a later fill — or an HTTP-auth challenge, which never prompts on its own —
// happen without a passphrase dialog.
const vaultEl = document.getElementById("vault");

function renderVault(locked) {
  vaultEl.hidden = false;
  vaultEl.disabled = false;
  vaultEl.textContent = locked ? "Unlock" : "Lock";
  vaultEl.dataset.locked = locked ? "yes" : "";
}

vaultEl.addEventListener("click", async () => {
  const wasLocked = vaultEl.dataset.locked === "yes";
  vaultEl.disabled = true;
  if (wasLocked) {
    // pinentry takes focus, which closes this popup; the unlock still
    // completes in the background script.
    showStatus("Enter your passphrase in the pinentry window…");
  }
  const result = await browser.runtime.sendMessage({
    cmd: wasLocked ? "unlock" : "lock",
  });
  if (!result || result.error) {
    showStatus(result ? result.error : "No response from the pw host.", true);
    vaultEl.disabled = false;
    return;
  }
  renderVault(result.locked);
  if (!result.locked) {
    showStatus("Vault unlocked.");
  } else if (wasLocked) {
    showStatus("Unlocked, but this host does not cache it (cache_minutes 0).");
  } else {
    showStatus("Vault locked.");
  }
});

async function refreshVault() {
  const result = await browser.runtime.sendMessage({ cmd: "status" });
  if (result && !result.error) renderVault(result.locked);
}

async function init() {
  let result;
  try {
    result = await browser.runtime.sendMessage({ cmd: "fill-request" });
  } catch (e) {
    showStatus("Error: " + e.message, true);
    return;
  }
  if (!result || result.error) {
    showStatus(result ? result.error : "No response from the pw host.", true);
    return;
  }
  if (result.filled) {
    showStatus(describeFill(result), !result.filled.filledPassword);
    setTimeout(() => window.close(), 900);
    return;
  }
  if (result.choices && result.choices.length) {
    showStatus("Choose a login:");
    renderChoices(result.choices);
    return;
  }
  showStatus("Nothing to fill.", true);
}

refreshVault();
init();
