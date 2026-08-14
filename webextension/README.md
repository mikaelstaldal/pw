# pw Firefox extension

The browser half of the pw Firefox integration. It holds no secrets and
contains no crypto: it asks the native host
`pw-browser-host` for the single login matching the active tab and fills it
into the page. The master passphrase is entered in a `pinentry` dialog outside
the browser, and only the matching entry is ever sent to the extension.

## Files

| File                          | Role                                                                            |
|-------------------------------|---------------------------------------------------------------------------------|
| `manifest.json`               | MV2 manifest; pins the extension ID `pw@staldal.nu`.                            |
| `background.js`               | Persistent background script; owns the native-messaging port, the fill flow and the HTTP-auth listener. |
| `popup.html` / `popup.js`     | Toolbar popup; shows status and the picker when more than one entry matches.    |
| `fill.js`                     | Injected into the active tab on demand to fill the form.                        |
| `options.html` / `options.js` | Options page; turns HTTP-authentication filling on and off.                     |
| `auth-permissions.js`         | The optional permissions that feature needs, shared by the two above.           |

## Install the native host first

```sh
pw install-browser
```

This writes the native-messaging manifest (`nu.staldal.pw.json`) pointing at
`pw-browser-host`, and a default `~/.config/pw/browser.json`. The manifest's
`allowed_extensions` pins `pw@staldal.nu`, so only this extension can talk to
the host.

## Load the extension

**Development (one browser session):**

1. Open `about:debugging` → *This Firefox* → *Load Temporary Add-on…*
2. Select `manifest.json` in this directory.

Or with [`web-ext`](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/):

```sh
web-ext run -s webextension
```

**Permanent:** Firefox only installs signed extensions. Submit the packaged
`.xpi` to addons.mozilla.org as an *unlisted* add-on; AMO signs it, and the
signed file can be installed from the GitHub releases page.

## Use

On a login page, click the toolbar button or press `Ctrl+Alt+L` (remappable in
`about:addons` → gear → *Manage Extension Shortcuts*). There is also a
*"Fill login with pw"* context-menu item.

The popup also has an **Unlock** button (it becomes **Lock** once the vault is
open). Unlocking there prompts for the master passphrase in `pinentry` without
filling anything and without releasing any entry, so the first fill of the
session does not have to be the thing that opens the vault. It is also the way
to make HTTP-authentication filling usable, since that path never prompts by
itself. Lock discards the host's decrypted copy immediately.

The host fills an entry only on a site that matches the entry's `url` — set only
from the CLI (never from the browser), which is what keeps the host read-only.
Only entries with a `url` are eligible; set the site with
`pw add <name> --url …` / `pw update <name> --url …` (the entry `name` is never
matched against the site). Fills then happen with no prompt until the host's
cache expires (`cache_minutes`, default 10).

## HTTP authentication (off by default)

Firefox's HTTP authentication prompt is browser chrome, not part of the page,
so no extension can type into it. What the extension can do instead is answer
the `401` before the prompt is shown, so it never appears.

That requires seeing requests to every site (`webRequest`, `webRequestBlocking`
and host permissions), which the extension does not ask for at install time.
Turn it on in `about:addons` → *pw* → *Preferences* (or the *Settings* link in
the popup) and Firefox asks you to grant them; the same page turns it back off,
as does *Permissions* in `about:addons`.

With it on, a challenge is answered only when **all** of these hold — otherwise
the normal dialog appears, exactly as it does today:

- it is a top-level page load, not an image, script, stylesheet or iframe, so
  an embedded resource cannot make Firefox submit your credentials in the
  background;
- the site is `https:` (or `http://localhost` / `http://127.0.0.1`), and it is
  a site challenge, not a proxy challenge;
- an entry's `url` names *exactly* that host. Unlike a form fill, a parent
  domain does not match: an entry for `example.com` is not released to
  `evil.example.com`, which a form fill would fill if you clicked to. Nothing
  here is a click, so a subdomain someone else controls must not be able to
  collect the parent domain's password silently;
- the vault is already unlocked. The request used here, `get-logins-strict`,
  is answered with `locked` rather than a passphrase prompt, so a page load
  cannot summon a `pinentry` dialog. Use the popup's **Unlock** button before
  you need it, or fill a form somewhere first;
- exactly one entry matches the site (there is no user gesture here, so the
  picker cannot be shown).

Credentials that the server rejects are not retried: the second challenge for
the same request falls through to the dialog.

When pw does answer, the toolbar button shows a green ✓ for three seconds once
the page has loaded — the only sign that it happened, since no dialog appears.
(The badge has to wait for the load: a tab's badge is cleared when the tab
navigates, and answering the challenge is part of that navigation.)

## Troubleshooting

Firefox discards the host's stderr, so to diagnose a fill that does nothing,
enable the host's debug log. Add a `log_file` to `~/.config/pw/browser.json`:

```json
{ "log_file": "~/pw-host.log" }
```

(or set `PW_BROWSER_LOG=/path/to/log`, which overrides it). The host then
appends, per request, its version, the environment it was launched with
(`DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, …), the full
pinentry exchange, and the outcome. The passphrase is never written — the
pinentry data line is reduced to its byte length. Remove `log_file` when done.

This is the place to look when a fill hangs: it shows whether the host reached
`pinentry`, what environment `pinentry` was given, and whether it returned a
passphrase or stalled.

## Limitations (phase 1)

- Top-level frame only; login forms inside cross-origin iframes are not filled.
- No form detection/highlighting, no save-on-submit, no password generation.
- Fields in closed shadow DOM are not reachable.
- HTTP authentication is answered only for a single match on a top-level load
  with the vault unlocked (see above); the realm is not matched, only the host.
