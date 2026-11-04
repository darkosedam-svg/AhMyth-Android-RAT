# AhMyth Android RAT — Threat Analysis & Detection Reference

> **Purpose and scope.** This is a defensive security research document. It
> explains how the AhMyth Android remote-access trojan (RAT) is built and how it
> behaves, so that analysts, blue teams, MDM/EDR authors, and students can
> **detect, attribute, and defend against** it. It deliberately contains **no
> deployment, targeting, evasion-hardening, or weaponization guidance**. Every
> claim is grounded in the source in this repository, with file references.
>
> AhMyth is widely abused as commodity Android malware. Using it against devices
> you do not own and are not explicitly authorized to test is illegal in most
> jurisdictions.

---

## 1. Executive summary

AhMyth is a two-part commodity Android RAT:

| Part | Tech | Role |
|------|------|------|
| **Server / control panel** (`AhMyth-Server/`) | Electron + AngularJS + `socket.io` | Operator GUI, C2 listener, and APK trojanizer ("APK Builder"). |
| **Client / backdoor** (`AhMyth-Client/`) | Native Android app (Java) | The implant installed on the victim device. Connects back to the C2 and services remote commands. |

The implant is a `socket.io` client that dials a hard-coded operator endpoint,
registers the device, and waits for short opcode "orders" (`x0000ca`, `x0000sm`,
…) that map to surveillance capabilities: camera capture, microphone recording,
SMS theft and sending, call-log and contact exfiltration, GPS location, and
arbitrary filesystem browse/download. It persists across reboots via a
`BOOT_COMPLETED` receiver and hides its launcher icon after first run.

The server can also **inject** the implant into a legitimate "carrier" APK by
decompiling it with `apktool`, merging AhMyth's permissions/components/`smali`,
and re-signing — producing a trojanized app that looks like the original.

This document is organized as: architecture → C2 protocol → capabilities →
persistence/stealth → trojanization mechanics → **detection opportunities**
(static, network, on-device, YARA sketch) → defensive guidance.

---

## 2. Architecture overview

```
                  socket.io over HTTP (default tcp/42474)
   ┌──────────────────────────┐        order: "x0000.."         ┌───────────────────────────┐
   │  AhMyth-Server (Electron) │  ───────────────────────────▶  │  AhMyth-Client (Android)   │
   │  - C2 listener            │                                 │  MainService (START_STICKY)│
   │  - Victim list / "Labs"   │  ◀───── emit: "x0000.." data ── │  ConnectionManager (router)│
   │  - APK Builder (apktool)  │        (photos, SMS, GPS, …)    │  per-capability Managers   │
   └──────────────────────────┘                                 └───────────────────────────┘
```

- **C2 listener** — `AhMyth-Server/app/main.js` starts a `socket.io` server on an
  operator-chosen port (default `42474`, `Constants.js:defaultPort`) on the
  `SocketIO:Listen` IPC event. Each inbound connection is turned into a "victim"
  record enriched with a GeoIP country lookup (`geoip-lite`).
- **Victim model** — `AhMyth-Server/app/app/assets/js/model/Victim.js` holds the
  live socket plus device metadata sent in the connection query string.
- **"Lab" windows** — per-victim operator UI (`LabCtrl.js`, `views/*.html`) that
  emits orders and renders returned data (e.g. a Leaflet map for GPS, an `<img>`
  for camera frames).
- **Implant service** — `MainService` (Android `Service`, `START_STICKY`) boots
  `ConnectionManager`, the command router.

---

## 3. Command-and-control protocol

### 3.1 Registration / beacon

The implant builds its C2 URL in
`AhMyth-Client/.../IOSocket.java`. Key observable traits:

- Transport is **`socket.io`** (Engine.IO) over plain **HTTP** — not TLS.
- The server address/port are **hard-coded into the APK at build time** (the
  builder string-replaces them; see §6). In the source skeleton the placeholder
  is `http://192.168.8.101:42474`.
- Device fingerprint is leaked **in the query string** of the handshake:

  ```
  http://<C2_HOST>:<C2_PORT>?model=<Build.MODEL>&manf=<Build.MANUFACTURER>
        &release=<Build.VERSION.RELEASE>&id=<Settings.Secure.ANDROID_ID>
  ```

  `ANDROID_ID` is used as the stable victim identifier (`main.js` reads it as
  `query.id`).
- Reconnection is aggressive and effectively indefinite:
  `reconnection = true`, `reconnectionDelay = 5000`,
  `reconnectionDelayMax = 999999999` (`IOSocket.java`).
- Liveness: server pings, implant replies `pong`
  (`ConnectionManager.sendReq()` registers a `ping`→`pong` handler;
  `main.js` sets `pingInterval = 10000`).

### 3.2 Order dispatch

Orders arrive as a JSON object on the `order` event; `ConnectionManager`
switches on the `order` field and an `extra` sub-selector. The opcode table
(from `ConnectionManager.java` and mirrored in `Constants.js:orders`):

| Opcode | Capability | `extra` / params | Result event |
|--------|------------|------------------|--------------|
| `x0000ca` | Camera | `camList` \| `0` (back) \| `1` (front) | `x0000ca` |
| `x0000fm` | File manager | `ls`+`path` \| `dl`+`path` | `x0000fm` |
| `x0000sm` | SMS | `ls` \| `sendSMS`+`to`+`sms` | `x0000sm` |
| `x0000cl` | Call logs | — | `x0000cl` |
| `x0000cn` | Contacts | — | `x0000cn` |
| `x0000mc` | Microphone | `sec` (duration) | (uploads recording) |
| `x0000lm` | Location (GPS) | — | `x0000lm` |

The fixed `x0000..` opcode namespace is a strong, stable **content signature**
(see §7). Results are returned by `socket.emit("<same opcode>", data)`.

---

## 4. Capability detail (what each module takes)

All capabilities are gated by Android runtime permissions declared in
`AndroidManifest.xml` (and re-added to carrier apps by the builder — §6).

- **Camera** (`CameraManager.java`) — opens the selected camera to an offscreen
  `SurfaceTexture(0)` (no visible preview), calls `takePicture`, JPEG-compresses
  the frame at quality 20, and emits it as a base64/`image` payload. `findCameraList`
  enumerates cameras. *Silent still capture*, front or back.
- **Microphone** (`MicManager.java`) — `MediaRecorder` with `AudioSource.MIC`,
  MPEG-4/AAC, writes a temp `sound*.mp3` into the app **cache dir**, records for
  an operator-specified number of seconds, then uploads.
- **SMS** (`SMSManager.java`) — reads `content://sms/inbox` via `ContentResolver`
  into `{phoneNo, msg}` pairs (full inbox exfiltration); `sendSMS` sends arbitrary
  texts via `SmsManager` (enables toll fraud / smishing propagation / OTP abuse).
- **Call logs** (`CallsManager.java`) and **Contacts** (`ContactsManager.java`) —
  bulk read of call history and the contact book.
- **Location** (`LocManager.java`) — `ACCESS_FINE_LOCATION`; returns
  `{enable, lat, lng}`; the operator UI plots it on a Leaflet map
  (`views/location.html`).
- **File manager** (`FileManager.java`) — `walk(path)` lists a directory as JSON
  (skips dot-files, includes a `../` parent entry); `downloadFile(path)`
  streams an arbitrary readable file back to the C2. Scope is whatever the
  storage permissions allow.

---

## 5. Persistence & stealth

Grounded in `AndroidManifest.xml`, `MainActivity.java`, `MainService.java`,
`MyReceiver.java`:

- **Icon hiding** — on first launch `MainActivity.onCreate()` starts the service,
  calls `finish()`, then `fn_hideicon()` which disables the launcher component
  (`setComponentEnabledSetting(..., COMPONENT_ENABLED_STATE_DISABLED, DONT_KILL_APP)`).
  The app disappears from the launcher after one run.
- **Boot persistence** — `MyReceiver` is a `BOOT_COMPLETED` `BroadcastReceiver`
  (`exported="true"`) that restarts `MainService` on every reboot.
- **Sticky service** — `MainService.onStartCommand` returns `START_STICKY`, so
  Android relaunches the service after it is killed.
- **Indefinite reconnect** — see §3.1; a transient network/C2 outage does not end
  the infection.

Note: these are legacy mechanisms. Modern Android (background-execution limits,
scoped storage, runtime-permission prompts, Play Protect, background-start
restrictions) blunts several of them — a useful fact for risk-rating but not an
excuse to assume immunity on older or side-loaded-friendly devices.

---

## 6. Trojanization ("APK Builder") mechanics — for recognition

The server can graft the implant onto a legitimate APK. Understanding the
mechanism lets analysts **recognize a trojanized app** and build repackaging
detections. From `AppCtrl.js` and `Constants.js`:

1. **Set C2** — `Build(ip, port)` opens the implant's
   `IOSocket.smali`, and string-replaces the URL between `http://` and
   `?model=` with the operator's `http://<ip>:<port>`. *Observation:* the C2 lives
   in that one `smali` file as a cleartext URL.
2. **Decompile carrier** — `apktool d` on the chosen APK.
3. **Merge manifest** — `copyPermissions()` adds any of AhMyth's 17 permissions
   not already present; a `<service>` for `MainService` is injected, and for the
   BOOT method a `<receiver>` with a `BOOT_COMPLETED` filter.
4. **Attach a trigger** — two binding methods:
   - **BOOT** (`BindOnBoot`) — rely on the injected boot receiver. "Works on
     almost every app."
   - **ACTIVITY** (`BindOnLauncher`) — locate the carrier's launcher activity
     (`GetLanucherPath`) and splice a `startService(...)` call into its
     `onCreate` `smali` (`serviceSrc`/`serviceStart`). Marked "unstable."
5. **Merge code** — copy AhMyth's `smali` tree into the carrier.
6. **Rebuild & sign** — `apktool b`, then `sign.jar` → `Ahmyth.s.apk`.

**Recognition signals of a repackaged carrier:** presence of the
`ahmyth/mine/king/ahmyth` package/`smali` path; a boot receiver + background
service that are unrelated to the app's stated function; a sudden permission
superset (camera+mic+SMS+contacts+call log+fine location) inconsistent with the
app's purpose; re-sign with a non-original (often debug/self-signed) certificate.

---

## 7. Detection opportunities

### 7.1 Static / APK indicators
- **Package & class path:** `ahmyth.mine.king.ahmyth` and classes
  `IOSocket`, `ConnectionManager`, `MainService`, `MyReceiver`, plus the
  capability managers (`CameraManager`, `MicManager`, `SMSManager`,
  `CallsManager`, `ContactsManager`, `LocManager`, `FileManager`).
- **Opcode strings:** the literal set
  `x0000ca x0000fm x0000sm x0000cl x0000cn x0000mc x0000lm` is highly specific.
- **Embedded C2 URL** in `IOSocket` of the form
  `http://<host>:<port>?model=…&manf=…&release=…&id=…`.
- **Permission constellation** (`Constants.permissions`): CAMERA, RECORD_AUDIO,
  READ_SMS, SEND_SMS, READ_CALL_LOG, READ_CONTACTS, ACCESS_FINE_LOCATION,
  READ/WRITE_EXTERNAL_STORAGE, RECEIVE_BOOT_COMPLETED, WAKE_LOCK — together with
  a hidden launcher activity.
- **Bundled `socket.io` client** for Java/Android.

### 7.2 Network indicators
- **Cleartext HTTP `socket.io`/Engine.IO** handshake carrying `model`, `manf`,
  `release`, and `id=<ANDROID_ID>` as query params — unusual and distinctive.
- Default port **`42474`** (operator-configurable; treat as a hint, not a rule).
- Engine.IO upgrade/`ping`/`pong` framing to a non-CDN, often bare-IP host.
- Short frames named `x0000*`; large base64 image/audio uploads on the same
  channel after an order.
- Because traffic is plaintext, **TLS inspection is not even required** —
  network sensors can match on the handshake and opcodes directly.

### 7.3 On-device / behavioral
- An installed app with **no launcher icon** that runs a sticky background
  service and a boot receiver.
- Camera/mic access with no foreground UI; repeated outbound beacons every ~few
  seconds after connectivity changes.
- MDM/EDR: flag apps whose granted permission set spans camera+mic+SMS+location
  +contacts with a hidden launcher component.

### 7.4 Illustrative YARA (Android DEX/APK text match — tune before use)

```yara
rule Android_AhMyth_RAT_indicators
{
    meta:
        description = "Heuristic indicators for AhMyth Android RAT implant"
        reference   = "defensive research; see docs/THREAT-ANALYSIS.md"
        category    = "android.rat"
    strings:
        $pkg   = "ahmyth/mine/king/ahmyth"
        $op1   = "x0000ca"
        $op2   = "x0000sm"
        $op3   = "x0000mc"
        $op4   = "x0000lm"
        $q     = "?model="
        $sock  = "io/socket/client/IO"
    condition:
        $pkg and $sock and $q and 3 of ($op*)
}
```

This is a starting sketch for triage, not a production rule — validate against a
clean corpus to gauge false positives, and pair with certificate/permission
heuristics.

---

## 8. Defensive guidance

**For users / device fleets**
- Install only from vetted stores; keep **Google Play Protect** on; avoid
  side-loading APKs from links/chat, the primary AhMyth delivery path.
- Scrutinize permission prompts — a flashlight/wallpaper app asking for SMS, mic,
  and call-log access is a red flag.
- Keep Android patched; newer versions materially reduce several AhMyth
  mechanisms (background start, scoped storage, one-time permissions).

**For blue teams / MDM / EDR**
- Deploy the static, network, and behavioral indicators in §7.
- Alert on side-loaded apps with hidden launchers + boot receivers + the
  surveillance permission constellation.
- Watch egress for cleartext `socket.io` handshakes with device-fingerprint
  query strings to bare-IP hosts; the plaintext protocol makes this tractable.
- Maintain an authorized-app / signing-certificate allowlist to catch
  repackaged carriers (§6).

**For responders**
- On suspicion: isolate the device from the network (kills the C2 channel),
  capture the APK and traffic for analysis, pull the embedded C2 URL from the
  implant's `IOSocket` class for pivoting/blocklisting, and treat all data the
  implant could reach (SMS/OTP, contacts, files, location, camera/mic) as
  potentially compromised. Rotate credentials and OTP-protected accounts.

---

## 9. Source references (this repository)

| Concern | File |
|---------|------|
| C2 URL, device fingerprint, reconnect policy | `AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/IOSocket.java` |
| Order routing / opcode table | `.../ConnectionManager.java` |
| Sticky service / app context | `.../MainService.java` |
| Boot persistence | `.../MyReceiver.java` |
| Icon hiding | `.../MainActivity.java` |
| Capabilities | `.../CameraManager.java`, `MicManager.java`, `SMSManager.java`, `CallsManager.java`, `ContactsManager.java`, `LocManager.java`, `FileManager.java` |
| Declared permissions / components | `AhMyth-Client/app/src/main/AndroidManifest.xml` |
| C2 listener, victim registration, GeoIP | `AhMyth-Server/app/main.js` |
| APK trojanizer / binding methods | `AhMyth-Server/app/app/assets/js/controllers/AppCtrl.js` |
| Opcodes, permissions, injection snippets, default port | `AhMyth-Server/app/app/assets/js/Constants.js` |
| Operator "Lab" UI / data rendering | `AhMyth-Server/app/app/assets/js/controllers/LabCtrl.js`, `AhMyth-Server/app/app/views/*.html` |

---

*Prepared as defensive/educational threat-intelligence documentation. Detection
artifacts (YARA, indicators) are provided for protective use and require tuning
against a known-good corpus before production deployment.*
