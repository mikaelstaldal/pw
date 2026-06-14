# pw Firefox extension

The browser half of the pw Firefox integration. It holds no secrets and
contains no crypto: it asks the native host
`pw-browser-host` for the single login matching the active tab and fills it
into the page. The master passphrase is entered in a `pinentry` dialog outside
the browser, and only the matching entry is ever sent to the extension.

## Files

| File                      | Role                                                                            |
|---------------------------|---------------------------------------------------------------------------------|
| `manifest.json`           | MV2 manifest; pins the extension ID `pw@staldal.nu`.                            |
| `background.js`           | Persistent background script; owns the native-messaging port and the fill flow. |
| `popup.html` / `popup.js` | Toolbar popup; shows status and the picker when more than one entry matches.    |
| `fill.js`                 | Injected into the active tab on demand to fill the form.                        |

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

The host fills an entry only on a site that matches the entry's `url` — set only
from the CLI (never from the browser), which is what keeps the host read-only.
Only entries with a `url` are eligible; set the site with
`pw add <name> --url …` / `pw update <name> --url …` (the entry `name` is never
matched against the site). Fills then happen with no prompt until the host's
cache expires (`cache_minutes`, default 10).

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
