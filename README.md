# 🛡 Sentinel

**AI-powered download security scanner for Windows.**

Sentinel silently monitors your Downloads folder and automatically analyzes every new file using the Groq AI API. It extracts content from scripts, documents, PDFs, archives, and executables, then delivers a real-time security verdict with a beautiful dark-themed notification.

---

## Features

- **Universal file scanning** — scripts, documents (`.docx`, `.xlsx`, `.pptx`), PDFs, archives (`.zip`), executables, images, shortcuts, and more
- **5-tier severity scale** — Informational · Low · Medium · High · Critical
- **Document summarization** — every file gets a brief AI-generated description
- **SHA-256 hashing** — binary files are fingerprinted for tracking
- **Beautiful notification UI** — dark-themed, color-coded alerts with auto-dismiss and countdown bar
- **Detailed reports** — saved as Markdown in `Documents\AI_Security_Reports`
- **Auto-start** — runs silently on boot via a VBScript in the Startup folder
- **Retry & fallback** — exponential backoff on API failures

## Setup

1. Clone this repo.
2. Replace `YOUR_API_KEY_HERE` in `ai_download_scanner.py` with your [Groq API key](https://console.groq.com/keys).
3. Run: `python ai_download_scanner.py`

## Requirements

- **Python 3.10+** (standard library only — zero pip installs)
- **Windows 10/11**
- **Groq API key** (free tier works)

## Files

| File | Purpose |
|---|---|
| `ai_download_scanner.py` | Main scanner loop, file extraction, AI analysis |
| `scanner_notification.py` | Tkinter-based notification UI (launched as subprocess) |

## License

MIT
