# SafeLine — CX1001 Final Functional Build v4.2

SafeLine is a public-space early-warning and prevention platform built around:

`Report → Integrity → Occurrence → Hours/Days/Weeks → Baseline + Context → Human Review → Action → Accountability → Monitoring`

This build is deliberately more than a reporting form. A citizen signal reaches an authority inbox, is acknowledged, checked for integrity, grouped into occurrences, compared with a real time-based baseline and context, reviewed by a human, converted into evidence-backed preventive action, and monitored afterward.

## Citizen workspace

- Automatic browser location detection starts as soon as the citizen page opens.
- No manual location entry and no separate Detect Location button for ordinary reporting.
- If GPS is unavailable or slow, the citizen can search the cached location list or enter a public place/landmark manually. The server still decides the final location grounding and ignores a distant client-supplied spot when GPS is present.
- The location watcher is cleared when the page closes/unmounts.
- Large floating **REPORT** and **SOS** controls sit at the lower-right for quick one-hand mobile access.
- Quick report: tapping a category submits a minimal report immediately; an 5-second undo window follows, and timing/self-witness/still-happening/context can be added afterward.
- Emergency Hub inspired by SafeHer: 112, location sharing, emergency siren, fake call from a trusted-contact name/Mother fallback, Women Helpline 181, safety message sharing, trusted contacts and a 15-minute check-in timer.
- Location sharing immediately records the assistance request in the authority workspace. On a real mobile browser, trusted-contact SMS is opened pre-addressed because a website cannot silently send SMS without the device messaging app's permission.
- Trusted contacts remain local to the browser for the prototype.
- Past reports are shown on the same device without creating an account. Clearing browser storage removes the local history link.
- Planning Mode gives a 30-day area snapshot: reported activity, distinct sources, categories and active concerns. It deliberately does not invent a numeric safety score.
- Dark mode remains available as a small top-bar preference.
- Location is never reverse-geocoded repeatedly while the page is open; the UI uses one submitted point only. If GPS is unavailable, the citizen can search cached demo locations or enter a public place/landmark manually.
- The authority workspace never requests, collects, or displays the authority device's current location. The incident map uses stored incident coordinates only.
- Citizen report receipts now show the automatically selected nearest authority, and the authority workspace identifies the active routed authority (for example, **Malvan Authority · Malvan Taluka**) from incoming report routing.

## Authority workspace

Demo authority logins:

- Duty Officer: `POLICE-042` / `1234`
- Station Supervisor: `POLICE-099` / `5678`

Evidence approval is role-separated: a duty officer cannot approve their own upload, and a supervisor cannot approve their own upload.

The PIN is stored as a salted PBKDF2 hash in the local SQLite database; the demo credential above is only for the prototype.

### Authority workflow

`New report → Acknowledge → Integrity review → Occurrence/pattern review → Human verification → Action planned → Evidence uploaded → Supervisor approval → Completed → Monitoring → Reopen if activity rises`

The citizen-facing report status mirrors this workflow. It no longer stays at **Review pending** after acknowledgement:

- Received
- Acknowledged by authority
- Under review
- Action in progress
- Completed
- Monitoring
- Reopened

### Fake / malicious reporting protection

SafeLine does **not** claim that an anonymous AI can determine whether a person is lying. Instead the actual scoring engine is `score_votes()` and it reduces the ability of raw volume to dominate a signal:

- repeated submissions from one pseudonymous token decay geometrically;
- token contribution is capped;
- one occurrence is treated as one episode, with corroboration capped instead of multiplying into N independent incidents;
- registered-spot, GPS and manual location grounding have different influence weights;
- first-seen token patterns are monitored over both time span and occurrence concentration;
- high temporal correlation, repeated-source influence and patient spaced-out source concentration are surfaced for reporting-pattern review;
- the server, not the browser, decides whether a report is registered-spot grounded or GPS-grounded;
- anonymous report handles are stored only as HMAC digests; the client token itself is never retained in SQLite;
- in-memory per-client rate limits slow report/help-now abuse without storing a persistent IP history.
- low-diversity bursts are not allowed to become automatic Priority decisions;
- the system never creates a named “suspected harasser” profile.

The **patient spaced-out flood** attack is explicitly included in the live Attack Lab. This matters because a simple “six reports in ten minutes” detector can be bypassed by waiting longer between submissions.

No anonymous system can prove a coordinated group is fake. The honest objective is to cap influence, expose suspicious structure, and require human verification before consequential action.

### Report content assistant

Authority report inspection includes a rule-based content assistant for optional citizen notes. It can flag things such as possible person-identifying content, very little context, or a possible category mismatch.

This is intentionally described as an **AI-assisted content pre-check**, not a truth detector.

### Completion evidence analysis

Completion evidence supports PDF, DOCX and TXT content extraction in the prototype. The content assistant checks whether the document contains terms relevant to the selected action, an obvious date, and the reported location when available.

It can return:

- content consistent;
- review recommended;
- action-content mismatch;
- no extractable text;
- other human-review flags.

Every uploaded evidence file is also SHA-256 hashed.

A document passing the content check does **not** prove that it is genuine. Completion remains hard-blocked until a supervisor approves the evidence. This is the reliable separation between automated assistance and authority accountability.

### Verification

Verification outcomes are persisted as structured records:

- Pattern confirmed
- Pattern not confirmed
- Insufficient evidence
- Context explains activity
- Reporting integrity concern

They are not silently stuffed into a free-text observation.

### Routing

Registered spots have an owner authority, backup authority and acknowledgement deadline. WATCH-only signals do not create meaningless overdue routing. REVIEW/PRIORITY concerns get a deadline; overdue routing is escalated to the backup authority. A meaningful new signal after monitoring/completion reopens the concern.

### Context

Authorities can record known events such as festivals, construction or examinations. Context events are read by the scoring engine so a legitimate spike can be explained rather than blindly treated as deterioration.

### Attack Lab

The Attack Lab is live, not a static JSX animation. It calls the same `score_votes()` engine used by production concern scoring and includes:

- Genuine slow build
- Coordinated flood
- Mixed genuine + coordinated
- Patient spaced-out flood
- One reporter repeating
- Festival/event spike
- New location / cold start
- Cross-spot corridor
- Post-intervention monitoring
- Adaptive attacker

## Backend setup — Python 3.13

```bat
cd backend
py -3.13 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Health endpoint:

`http://localhost:8000/api/health`

## Frontend setup

Open a second terminal:

```bat
cd frontend
npm install
npm run dev
```

Citizen:

`http://localhost:5173/`

Authority:

`http://localhost:5173/authority`

## Mac / Linux

```bash
./run_backend.sh
```

and in a second terminal:

```bash
./run_frontend.sh
```

## Judge/demo flow

1. Open the citizen page and allow browser location access.
2. When GPS is available, the current location is used for the report automatically. If GPS is unavailable or the browser is offline, SafeLine shows the location search/fallback picker instead.
3. Tap the floating **REPORT** control and submit a warning sign.
4. Open `/authority` and sign in with `POLICE-042` / `1234`.
5. The report appears under **New reports** as NEW.
6. Inspect the report and acknowledge it.
7. Confirm the citizen's Past Reports/status now changes to **Acknowledged by authority**.
8. Open the related concern and inspect integrity, effective signal, occurrences, baseline, context and routing.
9. Record a structured verification outcome.
10. Start verification / assign a preventive action.
11. Upload a completion report. Show the AI-assisted content pre-check and SHA-256 hash.
12. Supervisor-approve the evidence.
13. Only then mark the action Completed.
14. Move to Monitoring and demonstrate that the concern remains auditable.
15. Open Signal Integrity and run the **Patient spaced-out flood** attack.
16. Open Context and record a festival/construction event; the scoring engine incorporates the event.
17. Use Planning Mode on the citizen side to show the area snapshot without inventing a “safe score”.
18. Use the Emergency Hub separately from ordinary reporting.

## Important scope notes

- SafeLine does not replace 112 or claim automatic police dispatch.
- Emergency location sharing is a one-point assistance request, not continuous tracking.
- Trusted-contact SMS cannot be silently sent by an ordinary browser; the prototype opens the device's messaging composer with the recipient and message prepared.
- The check-in timer is a browser-level safety aid and cannot guarantee action if the browser/device is closed.
- Ordinary reports do not require a name, phone number, email or account.
- The browser pseudonymous token is not a proof of identity and can be regenerated; the integrity layer therefore treats token evidence as bounded influence, not truth.
- A completion document can be fabricated. SafeLine therefore does not equate “AI passed the document” with authenticity; the prototype requires structured observation, hash, content pre-check and supervisor approval.
- Planning data is reported activity, not proof that a place is safe or unsafe.
- The map uses OpenStreetMap/Leaflet and needs internet access. The authority map displays incident coordinates only; it does not use authority-device location.
- The demo police login is prototype authentication, not production police identity management.

## Demo seed

The supervisor-only demo seed clears the operational demo records and creates **exactly 38 reports** across the slow-build, coordinated-burst and unregistered-GPS examples. It also creates the demo context event and refreshes occurrences/alerts from the same scoring pipeline used by the workspace.

## Validation performed for this build

- Backend compiles under Python 3.13-compatible syntax.
- Authority login and hashed PIN verification tested.
- Automatic report workflow and acknowledgement status tested.
- Report history status mapping tested.
- `score_votes()` tested against coordinated, patient-spaced and repeated-source scenarios.
- Completion evidence upload, content analysis, SHA-256 hashing, supervisor approval and completion gate tested.
- Structured verification persistence tested.
- Context-event persistence and scoring refresh wired.
- Full Vite installation/build is environment-dependent; run `npm install` and `npm run dev` locally before the final demo.


## Tests

From `backend` with the virtual environment active:

```bat
pytest -q
```

The test suite covers server-side location normalisation, pseudonymous token hashing, anti-gaming scoring, supervisor-only destructive demo controls, and help-now rate limiting.

## Important scope notes

- SafeLine is an early-warning/prevention system, not a replacement for 112.
- The system does not decide that an anonymous report is true or false and does not identify a suspected person.
- Evidence analysis is content assistance only; SHA-256 proves file integrity, not real-world authenticity.
- Planning mode reports reported activity and active concerns; it deliberately does not produce a numeric safety score.
- Browser SMS sharing opens the device messaging app; a normal web page cannot silently send an SMS without user/device permission.

## Authority case handling — quick demo
1. Sign in as Duty Officer `POLICE-042` / `1234`.
2. Open **New reports** and select **Inspect** on the newest report.
3. Click **Acknowledge report**. The citizen's Past Reports status changes to **Acknowledged**.
4. Open the concern and click **Start verification**.
5. In **Human Verification**, choose an outcome and write what was actually checked.
6. Choose the action, then click **Assign action**.
7. Upload the completion/action record. Read the content-assistant result.
8. Sign out and sign in as Station Supervisor `POLICE-099` / `5678`.
9. Open the same concern and **Supervisor approve** the evidence.
10. Return to the Duty Officer account (or the authorised user) and click **Complete after evidence**.
11. The case becomes **Completed** and should then be monitored. New meaningful activity can reopen it.

### Evidence test file
Use the supplied sample `sample_evidence_lighting_inspection.docx` for a positive AI/content-assistant test. It is written for the **Lighting inspection** action at **University North Gate** and includes an action reference, date, location, findings and inspection terms. Upload it, then inspect the returned checks/flags before supervisor approval.


## v4.4 UI pass
- Citizen mode is isolated: the SafeLine brand returns to citizen home and the authority switch is hidden from citizen users.
- Authority workspace now uses a guided sidebar workflow instead of a dense multi-tab bar.
- Authority navigation is reduced to Command Center, workflow steps, Context Events, Integrity Lab, Map, Actions, Settings, and Citizen View.
- Larger case workspace, more whitespace, clearer step-by-step guidance.
- Citizen visual identity strengthened with layered pink surfaces, oversized editorial typography, floating SOS/report controls, and less generic card styling.

### Integrity note
SafeLine does not claim to prove a report is fake. Repeated/coordinated reporting is down-weighted, grouped into occurrences, surfaced as reporting-pattern review when appropriate, and kept behind human review. The Attack Lab demonstrates the same scoring function used by production scoring.

## Demo authority routing and map
- The Authority map shows the one-time incident location plus four synthetic demo authority branch locations around the Achra/Malvan area.
- A report is automatically assigned to the nearest registered demo authority branch; the assignment is stored on the report. Operational deployment would replace these synthetic branches with verified authority locations and jurisdiction data.
- The map displays the incident-to-nearest-branch relationship and nearby demo branches. It does not collect or display authority-device GPS.
- The map note explicitly identifies demo authority locations as synthetic prototype data.
- Offline reports use a client queue ID for idempotent relay, so a reconnect/retry cannot create the same offline report twice.
- The citizen report flow shows location first and places the category choices directly below it; there is no separate Continue-to-category tap.
### Final prototype routing/reporting notes
- Online citizen reporting uses one-time GPS automatically; there is no location-selection step while online.
- Offline citizen reporting uses cached/demo locations or a manual public place/landmark, then presents the category choices directly below the selected location.
- Authority map: incident points are red, the nearest/assigned demo authority branch is pink, and other registered demo branches are blue.
- Demo authority branch coordinates around Achra/Malvan are synthetic prototype data and are not real operational police locations. Production deployment would replace them with verified authority branch/jurisdiction data.
- Each report is automatically routed to the nearest registered demo authority branch based on the incident coordinates.
- Offline relay uses an idempotent queue ID so reconnect/retry cannot create the same report twice.

## Sharing / repository hygiene

- Do not share `backend/.token_secret`, `.env` files, private API keys, certificates, or locally generated session files.
- The packaged SQLite database is a **sanitized demo fixture** containing the 38 synthetic demo reports used by the prototype. Active authority sessions and assistance/contact event records were removed before packaging.
- The database will still be migrated/created automatically when the backend starts, and new runtime secrets are generated locally rather than shipped.
