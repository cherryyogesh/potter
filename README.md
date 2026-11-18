# Potter AI 2.0 — Local-first, multi-agent starter application

**Scope:** This is a **working browser/PWA development application**, not a native Android/iOS app, app-store release, biometric voice-identification system, or always-on assistant. All claims of guaranteed bug-free behavior would be misleading. Features marked not connected are genuinely not installed.

## Working capabilities

- Responsive mobile-first assistant UI with tap-to-talk and browser speech synthesis on supporting browsers
- Local text AI via configurable Ollama installation (optional)
- Offline calculator and local-time conversation agents
- Server-enforced Boss PIN and session-based protection for notes, reminders, tasks and guest names
- Private notes CRUD; tasks with completion toggles; reminders with timezone-aware ISO dates
- Due-reminder checks while the page is open and Boss is authenticated (notifications subject to browser permission)
- Consented guest **name** directory, removal and profile list (NOT voice biometrics)
- Agent availability dashboard; clear nonfunctional/unsupported-feature descriptions
- Same-origin write protection, login throttling, HTTP-only SameSite session cookie, 8-hour sessions
- Automated regression tests

## Installation

Prerequisites: Python 3.11+ (3.13 tested) and a modern browser. Run on a trusted local computer.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` from the **same computer**. Open the Vault and create a Boss PIN of at least 8 characters. Use a strong non-reused PIN/passphrase. Owner setup is limited to localhost by default.

### Enable local conversational AI

Install [Ollama](https://ollama.com/) and download a model your hardware supports:

```bash
ollama pull qwen3:4b
```

Then Potter can send prompts to the local Ollama HTTP endpoint. The local model is optional; clock, arithmetic, tasks, notes, reminders and access controls do not need it. Other model choices can be configured using `POTTER_OLLAMA_MODEL`.

## Tests

```bash
pip install pytest
pytest -q
```

## Security and operations

- **Do not expose the development server on a public network.** The PIN-based demo is not a production authentication system. In particular, the server has no account recovery or multi-device shared sessions.
- For a private HTTPS deployment behind an authenticated reverse proxy, configure `POTTER_SECURE_COOKIES=1`, proper TLS, trusted hosts and real authentication. Do not expose Ollama to the internet.
- Owner setup must take place from localhost; `POTTER_ALLOW_REMOTE_SETUP=1` is a developer escape hatch only.
- Data is stored in `data/potter.sqlite3` by default, or set `POTTER_DATA_DIR` to a private directory. **Data is not encrypted at rest**; use filesystem encryption, secure backups, and encrypted disks.
- Browser SpeechRecognition implementation varies and can rely on third-party cloud services. Use a self-hosted STT or native offline speech engine before claiming full audio privacy.
- Browser reminder notifications work only while the page is active; they are not reliable phone alarms or background push notifications.
- Guest voice registration is NOT implemented. Saved guest names are not proof of identity. Voice matches must never unlock private data.
- Third-party Android and iOS apps cannot universally replace system wake words, read other apps' private messages, or provide uninterrupted background microphone access.
- The Hugging Face speech-to-speech repository is a recommended **future** server adapter; not installed or bundled here.

## Next native milestones

1. Add native Kotlin Android assistant integration and Swift App Intents for Siri/Shortcuts with OS-specific permissions.
2. Build a realtime WebSocket adapter for Hugging Face speech-to-speech and verify on target hardware.
3. Add explicit consent-based, calibrated speaker verification; use it only for personalization.
4. Add secure production authentication (passkeys/biometrics), message and photo permissions scoped to the user, persistent audit logs, background notifications and backup strategy.
5. Test devices, networks, voice accuracy, failure handling, app-store requirements and security posture.

This codebase is a substantial runnable baseline, **not** a finished or independently deployed consumer app.
