import os
import time
import json
import urllib.request
import urllib.error
import subprocess
import ctypes

# --- CONFIGURATION ---
GROQ_API_KEY = "YOUR_API_KEY_HERE"
DOWNLOADS_DIR = os.path.expanduser(r"~\Downloads")
REPORTS_DIR = os.path.expanduser(r'~\Documents\AI_Security_Reports')
MODEL = "llama-3.3-70b-versatile"

IGNORE_EXTS = {".crdownload", ".part", ".opdownload", ".tmp"}
ANALYZE_EXTS = {".py", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".txt", ".sh", ".html"}

def setup():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        
def show_alert(title, message):
    # 0x30 = Warning Icon, 0x1000 = System Modal (forces window to front)
    # This will pause the thread until the user clicks OK, but that's fine for a critical alert
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x30 | 0x1000)

def analyze_with_ai(filepath, file_content):
    filename = os.path.basename(filepath)
    
    prompt = f"""
You are an expert cybersecurity analyst and malware reverse engineer.
Analyze the following code/file and determine if it is malicious, suspicious, or safe.
You MUST respond in valid JSON format ONLY with the following keys:
- "status": Must be exactly "Safe", "Suspicious", or "Malicious"
- "reason": A 1-2 sentence explanation of why.
- "action": What the user should do immediately (e.g., "Delete the file", "No action needed").
- "details": A detailed analysis of the code.

Filename: {filename}

File Content:
```
{file_content}
```
"""

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 2048,
        "response_format": {"type": "json_object"}
    }
    
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode("utf-8"))
                return json.loads(result["choices"][0]["message"]["content"])
        except urllib.error.HTTPError as e:
            if e.code in [429, 500, 502, 503, 504] and attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            return {"status": "Error", "reason": f"HTTP {e.code}", "action": "API failed", "details": ""}
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return {"status": "Error", "reason": str(e), "action": "Check network/API key", "details": ""}
    return {"status": "Error", "reason": "Max retries exceeded", "action": "Check network", "details": ""}

def process_file(filepath):
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in ANALYZE_EXTS:
        return

    time.sleep(2) # Wait for file write to complete
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        max_chars = 15000 
        if len(content) > max_chars:
            content = content[:max_chars] + "\n\n...[FILE TRUNCATED]..."
            
        result = analyze_with_ai(filepath, content)
        
        # Save the report
        report_filename = f"Report_{os.path.basename(filepath)}_{int(time.time())}.md"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as rf:
            rf.write(f"# Security Analysis Report for `{os.path.basename(filepath)}`\n\n")
            rf.write(f"**Status:** {result.get('status', 'Unknown')}\n\n")
            rf.write(f"**Action Required:** {result.get('action', 'None')}\n\n")
            rf.write(f"**Reason:** {result.get('reason', '')}\n\n")
            rf.write(f"## Detailed Analysis\n{result.get('details', '')}")
            
        # Trigger alert if malicious or suspicious
        status = result.get('status', '')
        if status in ['Malicious', 'Suspicious']:
            title = f"SECURITY ALERT: {status} File Detected!"
            msg = f"File: {os.path.basename(filepath)}\n\nReason: {result.get('reason', '')}\n\nACTION REQUIRED: {result.get('action', '')}\n\nCheck the full report in Documents\\AI_Security_Reports for details."
            show_alert(title, msg)
            
    except Exception as e:
        pass

def main():
    setup()
    seen_files = set()
    if os.path.exists(DOWNLOADS_DIR):
        seen_files = set(os.listdir(DOWNLOADS_DIR))
    
    try:
        while True:
            current_files = set(os.listdir(DOWNLOADS_DIR))
            new_files = current_files - seen_files
            
            for file in new_files:
                filepath = os.path.join(DOWNLOADS_DIR, file)
                _, ext = os.path.splitext(file)
                if ext.lower() not in IGNORE_EXTS:
                    process_file(filepath)
                seen_files.add(file)
                
            for file in current_files:
                if file not in seen_files:
                    _, ext = os.path.splitext(file)
                    if ext.lower() not in IGNORE_EXTS:
                        filepath = os.path.join(DOWNLOADS_DIR, file)
                        process_file(filepath)
                        seen_files.add(file)
            
            seen_files.intersection_update(current_files)
            time.sleep(3)
            
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

