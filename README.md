# Is This A Scam?

Paste a link. Get a score out of 100.

One input, one button, one answer. The app queries public reputation sources,
weighs what they say, and gives you a single number plus the evidence behind it.

## What it does

Type or paste a domain, a URL, or an email address. It resolves the domain and
runs it past every source below, in parallel.

| Source | What it tells us | Weight |
|---|---|---|
| **ScamAdviser** | 0-100 trust score; itself aggregates ~40 data sources | 0.55 |
| **Domain age (RDAP)** | registration date, registrar, status flags | 0.16 |
| **Phishing blacklist** | live OpenPhish feed of confirmed phishing URLs | 0.13 |
| **DNS records** | does it resolve, does it have MX/NS | 0.08 |
| **Archive history** | Wayback Machine presence | 0.04 |

The score is the weighted mean of the sources that answered. A source that is
unreachable is excluded rather than counted as zero, and the app prints the
arithmetic under the result so the number is never a black box.

### Guard rails

- **Confirmed phishing beats everything.** A domain in the OpenPhish feed is
  capped at 8/100 regardless of any other signal.
- **A dead domain is not a scam.** If the domain does not resolve, the verdict
  is "Cannot be verified" — with the honest caveat that a parked, expired or
  misconfigured domain is indistinguishable from an abandoned scam.
- **Household names are never flagged.** A small allow-list prevents an outage
  at one source from calling Google or PayPal a scam.

## Downloads

| Platform | File | Notes |
|---|---|---|
| Android | `dist/IsThisAScam.apk` | min SDK 24, target 34, signed. Share a link from any app straight into the checker. |
| Linux | `dist/Is This A Scam-1.0.0.AppImage` | portable, just `chmod +x` and run |
| Linux | `dist/is-this-a-scam_1.0.0_amd64.deb` | `sudo dpkg -i` |
| Windows | `dist/Is This A Scam Setup 1.0.0.exe` | NSIS installer |

## Building

Everything builds from source with no Gradle and no Android Studio.

```bash
# Android APK  (needs: JDK 17, Android SDK build-tools 34 + platform 34)
cd android && ANDROID_HOME=~/Android/Sdk bash build_apk.sh

# Linux + Windows  (needs: Node 18+)
cd electron && npm install && npm run dist
```

The APK chain is `aapt2 compile` -> `aapt2 link` -> `javac` -> `d8` -> `zipalign`
-> `apksigner`, and it produces a signed, installable package.

## Architecture

One engine, one interface, three shells.

```
app/
  core.js      the scoring engine — pure JS, no dependencies
  index.html   the interface
  ui.js        the interface logic
electron/      desktop shell (Linux + Windows)
android/       Android shell (WebView)
```

`core.js` and the UI are shared byte-for-byte between all three platforms.

### Why the shells exist

A page loaded from `file://` (Electron) or inside a WebView cannot call
ScamAdviser or OpenPhish directly: those hosts send no CORS headers, so
`fetch()` is blocked by the browser. Each shell therefore provides a native
transport, and `core.js` picks whichever one is present:

- **Electron** — `preload.js` exposes `window.__net.fetch()`, which runs in the
  main process where CORS does not apply. The main process restricts it to an
  allow-list of reputation hosts, so the page can never fetch an arbitrary URL.
- **Android** — the WebView intercepts `https://app.local/proxy?u=…` and does
  the request from Java, with the same host allow-list.
- **Plain browser** — falls back to direct `fetch()`, which works for the
  CORS-friendly sources.

## Privacy

No accounts, no analytics, no telemetry, no storage. The app sends the domain
you typed to the reputation services listed above and nothing else. There is no
server in the middle.

## Licence

MIT
