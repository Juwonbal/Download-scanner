"""
Sentinel â€” AI Download Scanner v2
Monitors the Downloads folder for ANY new file, extracts content based on type,
sends it to the Groq AI for security analysis and summarization, saves a report,
and triggers a beautiful notification alert.

Runs silently in the background via pythonw.exe.
"""

import os
import re
import sys
import time
import json
import struct
import hashlib
import zipfile
import tempfile
import subprocess

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

GROQ_API_KEY = "YOUR_API_KEY_HERE"
DOWNLOADS_DIR = os.path.expanduser(r"~\Downloads")
REPORTS_DIR   = os.path.expanduser(r"~\Documents\AI_Security_Reports")
NOTIFIER      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_notification.py")
MODEL         = "llama-3.3-70b-versatile"

# Python executable (use the real install, not the Windows Store stub)
PYTHONW = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Python", "pythoncore-3.14-64", "pythonw.exe")
if not os.path.exists(PYTHONW):
    PYTHONW = "pythonw.exe"

# Extensions still downloading â€” always skip
SKIP_EXTS = {".crdownload", ".part", ".opdownload", ".tmp"}

# â”€â”€ File categories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

SCRIPT_EXTS     = {".py", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".sh", ".wsf", ".reg"}
DOCUMENT_EXTS   = {".docx", ".doc"}
SPREADSHEET_EXTS = {".xlsx", ".xls"}
PRESENTATION_EXTS = {".pptx", ".ppt"}
PDF_EXTS        = {".pdf"}
TEXT_EXTS       = {".txt", ".csv", ".json", ".md", ".log", ".ini", ".cfg", ".yaml", ".yml", ".toml"}
WEB_EXTS        = {".html", ".htm", ".xml", ".svg", ".css"}
IMAGE_EXTS      = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".svg"}
ARCHIVE_EXTS    = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
EXECUTABLE_EXTS = {".exe", ".msi", ".dll", ".scr", ".com", ".pif"}
SHORTCUT_EXTS   = {".lnk"}


# â”€â”€ Utilities â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def format_size(size_bytes):
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def sha256(filepath):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unable_to_compute"


def file_ready(filepath, wait=2):
    """Wait for a file to finish writing (size stabilises)."""
    try:
        s1 = os.path.getsize(filepath)
        time.sleep(wait)
        s2 = os.path.getsize(filepath)
        return s1 == s2 and s2 > 0
    except Exception:
        return False


def categorize(ext):
    """Return (category_name, file_type_label) for a given extension."""
    ext = ext.lower()
    if ext in SCRIPT_EXTS:       return ("script",       "Script")
    if ext in DOCUMENT_EXTS:     return ("document",     "Document")
    if ext in SPREADSHEET_EXTS:  return ("spreadsheet",  "Spreadsheet")
    if ext in PRESENTATION_EXTS: return ("presentation", "Presentation")
    if ext in PDF_EXTS:          return ("pdf",          "PDF")
    if ext in TEXT_EXTS:         return ("text",         "Text")
    if ext in WEB_EXTS:          return ("web",          "Web")
    if ext in IMAGE_EXTS:        return ("image",        "Image")
    if ext in ARCHIVE_EXTS:      return ("archive",      "Archive")
    if ext in EXECUTABLE_EXTS:   return ("executable",   "Executable")
    if ext in SHORTCUT_EXTS:     return ("shortcut",     "Shortcut")
    return ("other", "Other")


# â”€â”€ Text Extraction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def extract_docx(filepath):
    """Extract text from .docx (OpenXML â€” ZIP of XML files)."""
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            if "word/document.xml" in z.namelist():
                xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
                text = re.sub(r"<[^>]+>", " ", xml)
                return re.sub(r"\s+", " ", text).strip()
    except Exception:
        pass
    return None


def extract_xlsx(filepath):
    """Extract text from .xlsx shared strings."""
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            texts = []
            if "xl/sharedStrings.xml" in z.namelist():
                xml = z.read("xl/sharedStrings.xml").decode("utf-8", errors="ignore")
                texts = re.findall(r"<t[^>]*>([^<]+)</t>", xml)
            return " ".join(texts) if texts else None
    except Exception:
        pass
    return None


def extract_pptx(filepath):
    """Extract text from .pptx slides."""
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            texts = []
            for name in sorted(z.namelist()):
                if name.startswith("ppt/slides/slide") and name.endswith(".xml"):
                    xml = z.read(name).decode("utf-8", errors="ignore")
                    texts.extend(re.findall(r"<a:t>([^<]+)</a:t>", xml))
            return " ".join(texts) if texts else None
    except Exception:
        pass
    return None


def extract_pdf(filepath):
    """Best-effort text extraction from PDF without external libraries."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(500_000)  # Read first 500KB
        # Extract printable string runs (4+ characters)
        runs = re.findall(rb"[\x20-\x7E]{4,}", data)
        # Filter out binary noise / PDF operators
        pdf_ops = {"stream", "endstream", "endobj", "xref", "startxref", "trailer"}
        readable = []
        for r in runs:
            s = r.decode("ascii", errors="ignore")
            if s.lower() not in pdf_ops and not s.startswith("/"):
                readable.append(s)
        return " ".join(readable[:600]) if readable else None
    except Exception:
        pass
    return None


def list_archive(filepath):
    """List contents of a ZIP archive."""
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            lines = []
            for info in z.infolist()[:100]:  # Cap at 100 entries
                lines.append(f"  {info.filename}  ({format_size(info.file_size)})")
            return "Archive contents:\n" + "\n".join(lines)
    except Exception:
        return None


def parse_lnk(filepath):
    """Extract the target path from a Windows .lnk shortcut."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        # Find path strings like C:\..., \\..., etc.
        paths = re.findall(rb"[A-Z]:\\[\x20-\x7E]{5,}", data)
        if paths:
            return "Shortcut target: " + paths[0].decode("ascii", errors="ignore")
        return "Shortcut target: could not parse"
    except Exception:
        return "Shortcut target: could not read file"


def check_double_extension(filename):
    """Detect suspicious double extensions like 'invoice.pdf.exe'."""
    parts = filename.rsplit(".", 2)
    if len(parts) >= 3:
        real_ext = "." + parts[-1].lower()
        decoy_ext = "." + parts[-2].lower()
        if real_ext in EXECUTABLE_EXTS and decoy_ext not in EXECUTABLE_EXTS:
            return f"DOUBLE EXTENSION DETECTED: appears as '{decoy_ext}' but is actually '{real_ext}'"
    return None


# â”€â”€ Content Builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def build_content(filepath, category, ext, file_size_str, file_hash):
    """Build the text content to send to the AI, based on file category."""

    filename = os.path.basename(filepath)
    header = f"Filename: {filename}\nFile Size: {file_size_str}\nSHA-256: {file_hash}\n"

    double_ext = check_double_extension(filename)
    if double_ext:
        header += f"WARNING: {double_ext}\n"

    # â”€â”€ Text-readable categories â”€â”€
    if category in ("script", "text", "web"):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(15_000)
            return header + f"\nFile Content:\n```\n{text}\n```"
        except Exception:
            return header + "\nCould not read file content."

    if category == "document":
        text = extract_docx(filepath)
        if text:
            return header + f"\nExtracted Document Text:\n{text[:12000]}"
        return header + "\nCould not extract document text."

    if category == "spreadsheet":
        text = extract_xlsx(filepath)
        if text:
            return header + f"\nExtracted Spreadsheet Data:\n{text[:12000]}"
        return header + "\nCould not extract spreadsheet data."

    if category == "presentation":
        text = extract_pptx(filepath)
        if text:
            return header + f"\nExtracted Presentation Text:\n{text[:12000]}"
        return header + "\nCould not extract presentation text."

    if category == "pdf":
        text = extract_pdf(filepath)
        if text:
            return header + f"\nExtracted PDF Text (best-effort):\n{text[:12000]}"
        return header + "\nCould not extract PDF text."

    # â”€â”€ Metadata-only categories â”€â”€
    if category == "archive":
        listing = list_archive(filepath)
        if listing:
            return header + f"\n{listing}"
        return header + "\nArchive type not supported for content listing (RAR/7z). Only metadata is available."

    if category == "executable":
        return header + "\nThis is a Windows executable binary. Content cannot be read as text."

    if category == "shortcut":
        target = parse_lnk(filepath)
        return header + f"\n{target}"

    if category == "image":
        return header + "\nThis is an image file. Only metadata is available."

    # other
    return header + "\nUnrecognised file type. Only metadata is available."


# â”€â”€ AI Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

SYSTEM_PROMPT = """You are Sentinel, an expert cybersecurity analyst and file inspector.
Analyze the provided file information and content. Respond ONLY with a JSON object, nothing else. No markdown, no explanation outside the JSON.

JSON keys:
{"severity": "...", "summary": "...", "reason": "...", "action": "...", "details": "..."}

severity must be one of: Informational, Low, Medium, High, Critical
summary: 2-3 sentences about what the file contains.
reason: 1-2 sentences explaining the security rating.
action: what the user should do.
details: technical analysis.

Severity Scale:
  Informational = Clean, no concerns.
  Low = Minor anomaly, likely safe.
  Medium = Suspicious patterns, review recommended.
  High = Likely malicious, immediate action needed.
  Critical = Confirmed malicious, delete immediately.

Rules:
- Executables (.exe, .msi, .dll) are Medium minimum.
- Scripts accessing browser data, Discord tokens, or webhooks are Critical.
- Archives containing executables or scripts are Medium minimum.
- Double extensions (e.g. invoice.pdf.exe) are High or Critical.
- Normal documents, images, text files are Informational if clean."""


def analyze_with_ai(filepath, content_text, file_type_label):
    """Send file content to Groq AI for analysis. Returns a dict."""

    user_msg = f"File Type: {file_type_label}\n\n{content_text}"

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.1,
        "max_tokens": 2048,
    }

    curl_cmd = [
        "curl.exe", "-s", "-X", "POST",
        "https://api.groq.com/openai/v1/chat/completions",
        "-H", f"Authorization: Bearer {GROQ_API_KEY}",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload),
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                curl_cmd, capture_output=True, text=True, encoding="utf-8",
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if result.returncode == 0 and result.stdout.strip():
                resp = json.loads(result.stdout)
                if "error" in resp:
                    msg = resp["error"].get("message", "Unknown API error")
                    return _error_result(f"API error: {msg}")

                raw = resp["choices"][0]["message"]["content"].strip()
                # Strip markdown fences if present
                if raw.startswith("```json"):
                    raw = raw[7:]
                if raw.startswith("```"):
                    raw = raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                return json.loads(raw.strip())
            else:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return _error_result(f"Curl failed: {result.stderr[:200]}")
        except json.JSONDecodeError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return _error_result("Failed to parse AI response as JSON")
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return _error_result(str(e))

    return _error_result("Max retries exceeded")


def _error_result(reason):
    return {
        "severity": "Error",
        "summary": "",
        "reason": reason,
        "action": "Check network / API key",
        "details": "",
    }


# â”€â”€ Notification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def send_notification(severity, filename, file_size, file_type, summary, action, report_path):
    """Launch the notification UI as a separate process."""

    alert_data = {
        "severity": severity,
        "filename": filename,
        "file_size": file_size,
        "file_type": file_type,
        "summary": summary,
        "action": action,
        "report_path": report_path,
    }

    # Write to a temp JSON file
    fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="sentinel_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(alert_data, f)

    try:
        subprocess.Popen(
            [PYTHONW, NOTIFIER, tmp_path],
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except Exception:
        # Fallback: show a basic MessageBox if notification UI fails
        try:
            import ctypes
            msg = f"File: {filename}\n\nSeverity: {severity}\n\n{summary}\n\nAction: {action}"
            ctypes.windll.user32.MessageBoxW(0, msg, f"Sentinel: {severity}", 0x30 | 0x1000)
        except Exception:
            pass


# â”€â”€ Report Writer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def write_report(filepath, result, file_size_str, file_type, file_hash):
    """Write a markdown report to the reports directory."""

    filename = os.path.basename(filepath)
    report_name = f"Report_{filename}_{int(time.time())}.md"
    report_path = os.path.join(REPORTS_DIR, report_name)

    severity = result.get("severity", "Unknown")
    severity_badge = {
        "Informational": "ðŸŸ¢ Informational",
        "Low":           "ðŸŸ¡ Low",
        "Medium":        "ðŸŸ  Medium",
        "High":          "ðŸ”´ High",
        "Critical":      "âš« Critical",
    }.get(severity, severity)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Sentinel Security Report\n\n")
        f.write(f"**File:** `{filename}`\n\n")
        f.write(f"**Size:** {file_size_str}\n\n")
        f.write(f"**Type:** {file_type}\n\n")
        f.write(f"**SHA-256:** `{file_hash}`\n\n")
        f.write(f"**Severity:** {severity_badge}\n\n")
        f.write(f"**Action:** {result.get('action', 'None')}\n\n")
        f.write(f"---\n\n")
        f.write(f"## Summary\n\n{result.get('summary', 'N/A')}\n\n")
        f.write(f"## Why This Rating\n\n{result.get('reason', 'N/A')}\n\n")
        f.write(f"## Technical Details\n\n{result.get('details', 'N/A')}\n\n")
        f.write(f"---\n\n")
        f.write(f"*Scanned by Sentinel at {time.strftime('%Y-%m-%d %H:%M:%S')}*\n")

    return report_path


# â”€â”€ File Processor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def process_file(filepath):
    """Analyse a single file: extract â†’ AI â†’ report â†’ notify."""

    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # Skip temp / in-progress downloads
    if ext in SKIP_EXTS:
        return

    # Skip directories
    if os.path.isdir(filepath):
        return

    # Wait for the file to finish downloading
    if not file_ready(filepath):
        return

    # Categorize
    category, file_type = categorize(ext)

    # File metadata
    try:
        size_bytes = os.path.getsize(filepath)
    except OSError:
        return
    file_size_str = format_size(size_bytes)
    file_hash = sha256(filepath)

    # Build content for AI
    content_text = build_content(filepath, category, ext, file_size_str, file_hash)

    # Send to AI
    result = analyze_with_ai(filepath, content_text, file_type)

    # Write report
    report_path = write_report(filepath, result, file_size_str, file_type, file_hash)

    # Send notification
    severity = result.get("severity", "Informational")
    send_notification(
        severity=severity,
        filename=filename,
        file_size=file_size_str,
        file_type=file_type,
        summary=result.get("summary", ""),
        action=result.get("action", ""),
        report_path=report_path,
    )


# â”€â”€ Main Loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Snapshot existing files so we only process NEW ones
    seen = set()
    if os.path.isdir(DOWNLOADS_DIR):
        seen = set(os.listdir(DOWNLOADS_DIR))

    while True:
        try:
            current = set(os.listdir(DOWNLOADS_DIR))
            new_files = current - seen

            for name in new_files:
                filepath = os.path.join(DOWNLOADS_DIR, name)
                try:
                    process_file(filepath)
                except Exception:
                    pass

            seen = current
            time.sleep(3)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
