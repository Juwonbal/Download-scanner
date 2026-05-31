"""
Sentinel — Security Notification UI
A beautiful, dark-themed notification window for the AI Download Scanner.
Launched as a subprocess by the main scanner script.

Usage: pythonw.exe scanner_notification.py <path_to_alert_json>
"""

import tkinter as tk
import json
import sys
import os
import winsound
from datetime import datetime


# ── Design Tokens ──────────────────────────────────────────────────────────────

COLORS = {
    'bg':           '#0d1117',
    'bg_card':      '#161b22',
    'border':       '#30363d',
    'text':         '#e6edf3',
    'text_muted':   '#8b949e',
    'text_dim':     '#484f58',
}

SEVERITY = {
    'Informational': {'color': '#238636', 'glow': '#0f2d16', 'icon': '✓',  'sound': False, 'dismiss': 6},
    'Low':           {'color': '#d29922', 'glow': '#3d2e00', 'icon': '◈',  'sound': False, 'dismiss': 10},
    'Medium':        {'color': '#db6d28', 'glow': '#3d1e00', 'icon': '◆',  'sound': True,  'dismiss': None},
    'High':          {'color': '#f85149', 'glow': '#3d0d0a', 'icon': '⬟',  'sound': True,  'dismiss': None},
    'Critical':      {'color': '#ff1a1a', 'glow': '#4a0000', 'icon': '⛔', 'sound': True,  'dismiss': None},
}

FILE_ICONS = {
    'Script':        '📜',
    'Document':      '📄',
    'Spreadsheet':   '📊',
    'Presentation':  '📊',
    'PDF':           '📕',
    'Image':         '🖼',
    'Archive':       '📦',
    'Executable':    '⚙',
    'Shortcut':      '🔗',
    'Text':          '📝',
    'Web':           '🌐',
    'Other':         '📁',
}

WIDTH = 420


# ── Notification Window ────────────────────────────────────────────────────────

class SentinelNotification:

    def __init__(self, data):
        self.data = data
        self.severity_key = data.get('severity', 'Informational')
        self.config = SEVERITY.get(self.severity_key, SEVERITY['Informational'])
        self.accent = self.config['color']

        self.root = tk.Tk()
        self._setup_window()
        self._build_ui()
        self._position_window()
        self._animate_in()

        if self.config['sound']:
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self.root.mainloop()

    # ── Window Setup ───────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title('Sentinel Alert')
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)
        self.root.attributes('-alpha', 0.0)
        self.root.configure(bg=COLORS['border'])

        # Allow dragging
        self._drag_x = 0
        self._drag_y = 0

    def _position_window(self):
        self.root.update_idletasks()
        w = WIDTH + 2   # +2 for outer border
        h = self.root.winfo_reqheight()
        sx = self.root.winfo_screenwidth()
        sy = self.root.winfo_screenheight()
        x = sx - w - 24
        y = sy - h - 64
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    # ── Build UI ───────────────────────────────────────────────────────────

    def _build_ui(self):
        # Outer border frame (1px border simulated by background color)
        outer = tk.Frame(self.root, bg=COLORS['border'])
        outer.pack(fill='both', expand=True, padx=0, pady=0)

        # Main card
        card = tk.Frame(outer, bg=COLORS['bg'])
        card.pack(fill='both', expand=True, padx=1, pady=1)

        # ── Top severity stripe ──
        tk.Frame(card, bg=self.accent, height=4).pack(fill='x')

        # ── Content area ──
        content = tk.Frame(card, bg=COLORS['bg'])
        content.pack(fill='both', expand=True, padx=20, pady=(14, 16))

        # Enable drag on content area
        for widget in [card, content]:
            widget.bind('<Button-1>', self._start_drag)
            widget.bind('<B1-Motion>', self._do_drag)

        # ── Header row: SENTINEL branding + close button ──
        header = tk.Frame(content, bg=COLORS['bg'])
        header.pack(fill='x')

        tk.Label(
            header, text='\u2666  SENTINEL', font=('Segoe UI', 9, 'bold'),
            fg=COLORS['text_dim'], bg=COLORS['bg']
        ).pack(side='left')

        close_btn = tk.Label(
            header, text='\u2715', font=('Segoe UI', 11),
            fg=COLORS['text_dim'], bg=COLORS['bg'], cursor='hand2'
        )
        close_btn.pack(side='right')
        close_btn.bind('<Button-1>', lambda e: self._dismiss())
        close_btn.bind('<Enter>', lambda e: close_btn.config(fg=COLORS['text']))
        close_btn.bind('<Leave>', lambda e: close_btn.config(fg=COLORS['text_dim']))

        # ── Severity badge ──
        sev_row = tk.Frame(content, bg=COLORS['bg'])
        sev_row.pack(fill='x', pady=(14, 0))

        badge_bg = self.config['glow']
        icon = self.config['icon']
        badge = tk.Label(
            sev_row, text=f'  {icon}  {self.severity_key.upper()}  ',
            font=('Segoe UI', 9, 'bold'),
            fg=self.accent, bg=badge_bg, padx=4, pady=2
        )
        badge.pack(side='left')

        # ── Filename ──
        file_icon = FILE_ICONS.get(self.data.get('file_type', 'Other'), '📁')
        filename = self.data.get('filename', 'Unknown')
        tk.Label(
            content, text=f'{file_icon}  {filename}',
            font=('Segoe UI', 13, 'bold'),
            fg=COLORS['text'], bg=COLORS['bg'], anchor='w'
        ).pack(fill='x', pady=(12, 0))

        # ── File metadata ──
        file_size = self.data.get('file_size', '')
        file_type = self.data.get('file_type', '')
        meta_parts = [p for p in [file_size, file_type] if p]
        if meta_parts:
            tk.Label(
                content, text='  \u00b7  '.join(meta_parts),
                font=('Consolas', 9), fg=COLORS['text_muted'], bg=COLORS['bg'], anchor='w'
            ).pack(fill='x', pady=(2, 0))

        # ── Separator ──
        tk.Frame(content, bg=COLORS['border'], height=1).pack(fill='x', pady=(14, 14))

        # ── Summary ──
        summary = self.data.get('summary', '')
        if summary:
            tk.Label(
                content, text=summary,
                font=('Segoe UI', 10), fg=COLORS['text'], bg=COLORS['bg'],
                anchor='nw', justify='left', wraplength=WIDTH - 48
            ).pack(fill='x')

        # ── Action ──
        action = self.data.get('action', '')
        if action:
            tk.Label(
                content, text=f'\u2192  {action}',
                font=('Segoe UI', 10, 'bold'), fg=self.accent, bg=COLORS['bg'],
                anchor='w', justify='left', wraplength=WIDTH - 48
            ).pack(fill='x', pady=(10, 0))

        # ── Buttons ──
        btn_frame = tk.Frame(content, bg=COLORS['bg'])
        btn_frame.pack(fill='x', pady=(16, 0))

        report_path = self.data.get('report_path', '')
        if report_path:
            view_btn = tk.Label(
                btn_frame, text='  View Report  ',
                font=('Segoe UI', 9, 'bold'), fg='#ffffff', bg=self.accent,
                padx=14, pady=6, cursor='hand2'
            )
            view_btn.pack(side='left', padx=(0, 8))
            view_btn.bind('<Button-1>', lambda e: self._view_report())
            view_btn.bind('<Enter>', lambda e: view_btn.config(bg=self._lighten(self.accent)))
            view_btn.bind('<Leave>', lambda e: view_btn.config(bg=self.accent))

        dismiss_btn = tk.Label(
            btn_frame, text='  Dismiss  ',
            font=('Segoe UI', 9), fg=COLORS['text_muted'], bg=COLORS['bg_card'],
            padx=14, pady=6, cursor='hand2'
        )
        dismiss_btn.pack(side='left')
        dismiss_btn.bind('<Button-1>', lambda e: self._dismiss())
        dismiss_btn.bind('<Enter>', lambda e: dismiss_btn.config(fg=COLORS['text']))
        dismiss_btn.bind('<Leave>', lambda e: dismiss_btn.config(fg=COLORS['text_muted']))

        # ── Timestamp ──
        ts = datetime.now().strftime('%I:%M %p')
        tk.Label(
            content, text=f'Scanned at {ts}',
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg'], anchor='w'
        ).pack(fill='x', pady=(12, 0))

        # ── Auto-dismiss countdown bar ──
        dismiss_secs = self.config['dismiss']
        if dismiss_secs:
            bar_track = tk.Frame(card, bg=COLORS['bg_card'], height=3)
            bar_track.pack(fill='x', side='bottom')

            self._bar = tk.Frame(bar_track, bg=self.accent, height=3)
            self._bar.place(relwidth=1.0, relheight=1.0)

            total_steps = dismiss_secs * 20  # 50ms per step
            def _tick(step=0):
                if step < total_steps:
                    try:
                        self._bar.place(relwidth=1.0 - step / total_steps, relheight=1.0)
                        self.root.after(50, lambda: _tick(step + 1))
                    except tk.TclError:
                        pass
                else:
                    self._dismiss()
            self.root.after(600, _tick)  # Start after fade-in

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _lighten(hex_color, amount=30):
        """Lighten a hex color slightly for hover effects."""
        hex_color = hex_color.lstrip('#')
        r = min(255, int(hex_color[0:2], 16) + amount)
        g = min(255, int(hex_color[2:4], 16) + amount)
        b = min(255, int(hex_color[4:6], 16) + amount)
        return f'#{r:02x}{g:02x}{b:02x}'

    def _start_drag(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def _do_drag(self, event):
        x = self.root.winfo_x() + event.x - self._drag_x
        y = self.root.winfo_y() + event.y - self._drag_y
        self.root.geometry(f'+{x}+{y}')

    def _animate_in(self):
        alpha = 0.0
        def _fade():
            nonlocal alpha
            alpha += 0.06
            if alpha < 1.0:
                try:
                    self.root.attributes('-alpha', alpha)
                    self.root.after(12, _fade)
                except tk.TclError:
                    pass
            else:
                try:
                    self.root.attributes('-alpha', 1.0)
                except tk.TclError:
                    pass
        _fade()

    def _view_report(self):
        path = self.data.get('report_path', '')
        if path and os.path.exists(path):
            os.startfile(path)

    def _dismiss(self):
        try:
            self.root.destroy()
        except Exception:
            pass


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(1)

    json_path = sys.argv[1]
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Clean up the temp JSON
        try:
            os.remove(json_path)
        except OSError:
            pass

        SentinelNotification(data)

    except Exception:
        sys.exit(1)
