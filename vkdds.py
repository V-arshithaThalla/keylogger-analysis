import os
import re
import csv
import time
import psutil
import smtplib
import threading
import webbrowser
import ctypes
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import Tk

alert_shown = False  # global flag to prevent repeat alerts

def show_alert_once():
    global alert_shown
    if alert_shown:  # if already shown once, don't show again
        return
    alert_shown = True  # mark as shown

    root = Tk()
    root.withdraw()  # hide main window
    messagebox.showwarning("Warning", "Suspicious activity detected!")
    root.destroy()


# Notifications
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except Exception:
    PLYER_AVAILABLE = False

# Optional: for active window title (heuristic)
try:
    import pygetwindow as gw
    GW_AVAILABLE = True
except Exception:
    GW_AVAILABLE = False

# ---------------------------
# Configuration
# ---------------------------
SCAN_INTERVAL = 5

# requested (preferred) location for logs
_REQUESTED_LOG_DIR = Path.cwd() / "vkdds_logs"

def make_log_dir(requested: Path) -> Path:
    """
    Try to create the requested log directory. On permission errors
    fall back to a safe location in the user's home directory.
    Returns the actual directory used.
    """
    try:
        requested.mkdir(parents=True, exist_ok=True)
        # extra check: can we write a temp file there?
        test_file = requested / ".vkdds_write_test"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("test")
        test_file.unlink(missing_ok=True)
        print(f"[vkdds] Using log dir: {requested}")
        return requested
    except PermissionError:
        fallback = Path.home() / "vkdds_logs"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            print(f"[vkdds] Permission denied for {requested}; using fallback: {fallback}")
            return fallback
        except Exception as e:
            # Last resort: use cwd (may still fail); raise if nothing works
            print(f"[vkdds] Failed to create fallback log dir ({e}). Attempting cwd.")
            cwd_dir = Path.cwd() / "vkdds_logs_fallback"
            cwd_dir.mkdir(parents=True, exist_ok=True)
            print(f"[vkdds] Using fallback cwd dir: {cwd_dir}")
            return cwd_dir
    except Exception as e:
        # Any other error: fallback to home
        fallback = Path.home() / "vkdds_logs"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            print(f"[vkdds] Error creating requested log dir ({e}); using fallback: {fallback}")
            return fallback
        except Exception as e2:
            cwd_dir = Path.cwd() / "vkdds_logs_fallback"
            cwd_dir.mkdir(parents=True, exist_ok=True)
            print(f"[vkdds] Using fallback cwd dir: {cwd_dir}")
            return cwd_dir

LOG_DIR = make_log_dir(_REQUESTED_LOG_DIR)
SIM_LOG_FILE = LOG_DIR / "simulated_keylog.txt"
CSV_LOG_FILE = LOG_DIR / "categorized_keylog.csv"

SUSPICIOUS_KEYWORDS = [
    "keylog", "pynput", "keyboard", "win32api", "hook", "pyHook",
    "python.exe", "python", "logkeys", "keystroke", "logger"
]

EMAIL_ENABLED = False
EMAIL_SMTP = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = "23wh1a1247@bvrithyderabad.edu.in"
EMAIL_APP_PASSWORD = "loxrejimhofhgkbm"
EMAIL_TO = "ksriharshini1110@gmail.com"

# ---------------------------
# Utilities
# ---------------------------
def notify(title, message, timeout=6):
    try:
        if PLYER_AVAILABLE:
            notification.notify(title=title, message=message, timeout=timeout)
            return
    except Exception:
        pass
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(title, message)
        root.destroy()
    except Exception:
        print(f"[NOTIFY] {title}: {message}")

def send_email(subject, body, attachment_path: Path = None):
    if not EMAIL_ENABLED:
        print("[email] Disabled")
        return False, "disabled"
    if not EMAIL_USER or not EMAIL_APP_PASSWORD:
        return False, "missing credentials"
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject
        msg.set_content(body)
        if attachment_path and attachment_path.exists():
            with open(attachment_path, "rb") as f:
                data = f.read()
            msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=attachment_path.name)
        with smtplib.SMTP(EMAIL_SMTP, EMAIL_PORT, timeout=20) as s:
            s.ehlo()
            s.starttls()
            s.login(EMAIL_USER, EMAIL_APP_PASSWORD)
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        print(f"[email] send failed: {e}")
        return False, str(e)

def scan_processes():
    detected = []
    for proc in psutil.process_iter(['pid','name','exe','cmdline']):
        try:
            info = proc.info
            name = (info.get("name") or "")
            cmd = " ".join(info.get("cmdline") or [])
            combined = f"{name} {cmd}".lower()
            if name.lower() in ("python.exe","python"):
                detected.append(info)
                continue
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in combined:
                    detected.append(info)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return detected

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=5)
        return True, None
    except Exception as e:
        return False, str(e)

# ---------------------------
# Categorization
# ---------------------------
SITE_RE = re.compile(r"(https?://[^\s/]+|[^\s]+\.(com|in|org|net|io)\b)", re.IGNORECASE)
USERNAME_RE = re.compile(r"\buser(name)?[:=]\s*(\w{2,})\b", re.IGNORECASE)
PASSWORD_RE = re.compile(r"\bpass(word)?[:=]\s*(\S{3,})\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

def categorize_line(line:str, window_title:str=None):
    l = line.strip()
    if not l: return "empty", ""
    m = PASSWORD_RE.search(l)
    if m: return "password", m.group(2)
    m = USERNAME_RE.search(l)
    if m: return "username", m.group(2)
    m = EMAIL_RE.search(l)
    if m: return "email", m.group(0)
    m = SITE_RE.search(l)
    if m: return "site", m.group(0)
    if window_title:
        wt = window_title.lower()
        if "login" in wt or "sign in" in wt: return "credentials", l
        if any(b in wt for b in ("chrome","firefox","browser","mozilla")): return "website_text", l
    return "conversation", l

def append_sim_log(line:str):
    with open(SIM_LOG_FILE,"a",encoding="utf-8") as f:
        f.write(line+"\n")

def append_csv_row(timestamp, window_title, text, category):
    new_file = not CSV_LOG_FILE.exists()
    with open(CSV_LOG_FILE,"a",newline="",encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp","window_title","text","category"])
        writer.writerow([timestamp, window_title or "", text, category])

# ---------------------------
# VKDDS GUI
# ---------------------------
class VKDDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Analysis")
        self.root.geometry("1024x680")
        self.root.minsize(900,600)

        self.auto_block_var = tk.BooleanVar(value=False)
        self.email_enabled_var = tk.BooleanVar(value=EMAIL_ENABLED)

        self.setup_styles()
        self.tabs = ttk.Notebook(root)
        self.tab_info = ttk.Frame(self.tabs)
        self.tab_dash = ttk.Frame(self.tabs)
        self.tab_sim = ttk.Frame(self.tabs)
        self.tab_email = ttk.Frame(self.tabs)

        self.tabs.add(self.tab_info, text="Project Information")
        self.tabs.add(self.tab_dash, text="🛡Detection Dashboard")
        self.tabs.add(self.tab_sim, text="🔬 Keylogger Simulation")
        self.tabs.add(self.tab_email, text="📧 Email Alerts")

        self.tabs.pack(expand=True, fill="both")

        self.setup_info_tab()
        self.setup_dashboard_tab()
        self.setup_sim_tab()
        self.setup_email_tab()

        self.scanner_thread = threading.Thread(target=self.scanner_loop, daemon=True)
        self.scanner_thread.start()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#a0c4ff")
        style.configure("TNotebook.Tab", padding=[12, 8], font=("Segoe UI", 11, "bold"),
                        background="#a0c4ff", foreground="#000000")
        style.map("TNotebook.Tab", background=[("selected", "#a0c4ff")], foreground=[("selected", "#000000")])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#a0c4ff", foreground="black")
        style.configure("Treeview", font=("Segoe UI", 10), background="#a0c4ff", fieldbackground="#a0c4ff")
        style.configure("TButton", font=("Segoe UI", 10), background="#a0c4ff", foreground="black")
        style.map("TButton", background=[("active", "#a0c4ff")], foreground=[("active", "black")])
        style.configure("TLabel", font=("Segoe UI", 10), background="#a0c4ff")
        style.configure("TCheckbutton", font=("Segoe UI", 10), background="#a0c4ff")
        style.configure("TFrame", background="#a0c4ff")
        self.root.configure(bg="#a0c4ff")
# --- Fixed white backgrounds ---
        style.configure("Treeview",
                font=("Segoe UI", 10),
                background="#dbe9ff",
                fieldbackground="#dbe9ff",
                foreground="black",
                rowheight=24)
        style.map("Treeview",
          background=[("selected", "#5dade2")],
          foreground=[("selected", "white")])

        style.configure("TEntry",
                fieldbackground="#dbe9ff",
                background="#dbe9ff",
                foreground="black")

        style.configure("TLabel", font=("Segoe UI", 10), background="#a0c4ff", foreground="black")
        style.configure("TFrame", background="#a0c4ff")
        self.root.configure(bg="#a0c4ff")
                         

    
        # ----------------- Project Info -----------------
    def setup_info_tab(self):
        frame = ttk.Frame(self.tab_info, padding=12)
        frame.pack(fill="both", expand=True)

    # --- Top frame for title/description + button ---
        top_frame = ttk.Frame(frame)
        top_frame.pack(fill="x", pady=(0, 12))

    # --- Centered title and description ---
        title_desc_frame = ttk.Frame(top_frame)
        title_desc_frame.pack(anchor="center", pady=(20, 12))

        ttk.Label(title_desc_frame, text="Keylogger Analysis",
          font=("Segoe UI", 18, "bold")).pack(anchor="center", pady=(0, 6))

        desc = ("Safe simulation tool to test detection of keylogger activity.\n"
            "Click the button below to open the project information report.")
        ttk.Label(title_desc_frame, text=desc, wraplength=600, justify="center", font=("Segoe UI", 11)).pack(anchor="center")

    # --- Button centered below title/description ---
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(anchor="center", pady=(12, 0))

        open_btn = ttk.Button(
        button_frame,
        text="Open Project Report",
        command=self.open_project_info_report
        )
        open_btn.pack(pady=10)

    # Make button bigger (font + padding)
        style = ttk.Style()
        style.configure("Big.TButton",
                font=("Segoe UI", 14, "bold"),
                padding=(20, 10),
                background="#4A90E2",
                foreground="black")
        style.map("Big.TButton",
              background=[("active", "#357ABD")],
              foreground=[("active", "black")])
        open_btn.configure(style="Big.TButton")

    # --- Load image safely ---
        image_path = r"C:\Users\hp\Downloads\vkdds_logo.jpg"  # update path
        if Path(image_path).exists():
            try:
                from PIL import Image, ImageTk
                img = Image.open(image_path)
                img = img.resize((1175, 425))  # adjust size to fit window
                self.logo_img = ImageTk.PhotoImage(img, master=frame)  # set master to avoid timing issues
                logo_label = ttk.Label(frame, image=self.logo_img, background="#a0c4ff")
                logo_label.pack(anchor="center", pady=(10, 10))
            except Exception as e:
                print(f"[info_tab] Could not load image: {e}")
        else:
            print(f"[info_tab] Image file not found: {image_path}")

    
    
    def open_project_info_report(self):
        import tempfile
        import webbrowser
        from pathlib import Path

    # create file in a temp location
        temp_dir = Path(tempfile.gettempdir())
        html_file = temp_dir / "project_report.html"

        html_content = """<html>
<head><title>Project Information</title></head>
<body style="font-family: Arial, sans-serif; margin: 20px;">
<div style="display: flex; justify-content: space-between; align-items: center;">
    <h2>Project Information</h2>
    <img src="C:\\Users\\hp\\OneDrive\\Pictures\\SuprajaLogo_fixed.jpg" style="height:80px; width:auto;"/> 
</div>
<p>This project was developed by <b>SriHarshini, Varshitha, Anjali, Shyamala and Sahasra</b> as part of a <b>Cyber Security Internship</b>. This project is designed to <b>Secure Organizations from Cyber Frauds</b>.</p>
<h3>Project Details</h3>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<tr><th>Project Details</th><th>Value</th></tr>
<tr><td>Project Name</td><td>KeyLogger Analyser - Detector</td></tr>
<tr><td>Project Description</td><td>Detecting keyloggers by monitoring unusual keystroke logging behaviors, unauthorized access to input devices, and suspicious background processes.</td></tr>
<tr><td>Project Start Date</td><td>01-June-2025</td></tr>
<tr><td>Project End Date</td><td>10-October-2025</td></tr>
<tr><td>Project Status</td><td>Completed</td></tr>
</table>
<h3>Developer Details</h3>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
<tr><td>SriHarshini</td><td>23wh1a1247</td><td>23wh1a1247@bvrithyderabad.edu.in</td></tr>
<tr><td>Varshitha</td><td>23wh1a1246</td><td>23wh1a1246@bvrithyderabad.edu.in</td></tr>
<tr><td>Anjali</td><td>23wh1a1208</td><td>23wh1a1208@bvrithyderabad.edu.in</td></tr>
<tr><td>Shyamala</td><td>23wh1a1299</td><td>23wh1a1299@bvrithyderabad.edu.in</td></tr>
<tr><td>Sahasra</td><td>23wh1a1203</td><td>23wh1a1203@bvrithyderabad.edu.in</td></tr>
</table>
<h3>Company Details</h3>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<tr><th>Company</th><th>Value</th></tr>
<tr><td>Name</td><td>Supraja Technologies</td></tr>
<tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
</table>
</body></html>"""

        html_file.write_text(html_content, encoding="utf-8")
        webbrowser.open_new_tab(html_file.as_uri())

    
    # ----------------- Detection Dashboard -----------------
    def setup_dashboard_tab(self):
        top = ttk.Frame(self.tab_dash, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Scanner Status:").pack(side="left")
        self.scan_status_var = tk.StringVar(value="Idle")
        ttk.Label(top, textvariable=self.scan_status_var).pack(side="left", padx=(6,20))
        ttk.Button(top, text="Rescan Now", command=self.manual_scan).pack(side="left")
        ttk.Button(top, text="Export Suspicious CSV", command=self.export_suspicious).pack(side="left", padx=(6,0))

        cols = ("pid","name","exe","cmd")
        self.proc_tree = ttk.Treeview(self.tab_dash, columns=cols, show="headings", height=12)
        for c,w in zip(cols,(80,220,320,360)):
            self.proc_tree.heading(c,text=c.upper())
            self.proc_tree.column(c,width=w)
        self.proc_tree.pack(fill="both",expand=True,pady=8,padx=8)

        ctrl = ttk.Frame(self.tab_dash, padding=8)
        ctrl.pack(fill="x")
        ttk.Button(ctrl, text="Kill Selected", command=self.kill_selected).pack(side="left")
        ttk.Checkbutton(ctrl, text="Auto-Block Suspicious Processes", variable=self.auto_block_var).pack(side="left", padx=(10,0))
        ttk.Button(ctrl, text="Open Logs Folder", command=lambda: os.startfile(str(LOG_DIR))).pack(side="left", padx=(10,0))
        self.dashboard_bar = ttk.Label(self.tab_dash, text="Ready")
        self.dashboard_bar.pack(side="bottom", fill="x")

    def manual_scan(self):
        procs = scan_processes()
        self.update_proc_tree(procs)
        self.dashboard_bar.config(text=f"Manual scan found {len(procs)} suspicious processes")

    def update_proc_tree(self, proc_list):
        for iid in self.proc_tree.get_children():
            self.proc_tree.delete(iid)
        for p in proc_list:
            cmd = " ".join(p.get("cmdline") or [])
            iid = self.proc_tree.insert("", "end", values=(p.get("pid",""), p.get("name",""), p.get("exe",""), cmd))
            # Color suspicious processes
            combined = f"{p.get('name','')} {cmd}".lower()
            if any(kw.lower() in combined for kw in SUSPICIOUS_KEYWORDS):
                self.proc_tree.item(iid, tags=("suspicious",))
        self.proc_tree.tag_configure("suspicious", background="#dbe9ff")  # light blue

    def export_suspicious(self):
        procs = scan_processes()
        if not procs:
            messagebox.showinfo("Export", "No suspicious processes to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialdir=LOG_DIR, filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path,"w",encoding="utf-8") as f:
            f.write("pid,name,exe,cmdline\n")
            for p in procs:
                f.write(f'{p.get("pid","")},"{p.get("name","")}","{p.get("exe","")}","{" ".join(p.get("cmdline") or [])}"\n')
        messagebox.showinfo("Exported", f"Saved to {path}")

    def kill_selected(self):
        sel = self.proc_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a process first."); return
        for s in sel:
            pid = int(self.proc_tree.item(s)["values"][0])
            ok, err = kill_process(pid)
            if ok: notify("VKDDS", f"Terminated process {pid}")
            else: messagebox.showwarning("Fail", f"Failed to terminate {pid}: {err}")

    def scanner_loop(self):
        while True:
            try:
                self.scan_status_var.set("Scanning...")
                procs = scan_processes()
                self.update_proc_tree(procs)
                if procs:
                    self.scan_status_var.set(f"Detected {len(procs)} suspicious")
                    for p in procs:
                        pid = p.get("pid")
                        name = p.get("name","")
                        if self.auto_block_var.get():
                            ok, err = kill_process(pid)
                            if ok: notify("VKDDS Alert", f"Auto-blocked {name} (PID {pid})")
                            if EMAIL_ENABLED: send_email(subject=f"VKDDS Auto-Block: {name}", body=f"Auto-blocked {name} (PID {pid})")
                        else:
                            show_alert_once()
                            if EMAIL_ENABLED: send_email(subject=f"VKDDS Suspicious: {name}", body=f"Detected suspicious process: {name} (PID {pid})")
                else:
                    self.scan_status_var.set("No suspicious processes")
                self.dashboard_bar.config(text=f"Last scan: {time.strftime('%H:%M:%S')} | Detected: {len(procs)}")
            except Exception as e:
                print(f"[scanner] error: {e}")
            time.sleep(SCAN_INTERVAL)

    # ----------------- Simulation Tab -----------------
    def setup_sim_tab(self):
        top_frame = ttk.Frame(self.tab_sim, padding=10)
        top_frame.pack(fill="x")
        ttk.Label(top_frame, text="Safe simulated input:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        buttons = ttk.Frame(top_frame)
        buttons.pack(anchor="e", pady=(6,0))
        ttk.Button(buttons,text="Process Input",command=self.process_sim_input).pack(side="left", padx=(0,6))
        ttk.Button(buttons,text="Generate Test Data",command=self.generate_test_data).pack(side="left", padx=(0,6))
        ttk.Button(buttons,text="Clear",command=lambda:self.sim_text.delete("1.0",tk.END)).pack(side="left")

        self.sim_text = tk.Text(self.tab_sim,height=10, wrap="word", font=("Consolas", 10))
        self.sim_text.pack(fill="x", padx=8, pady=(6,8))
        
# UPDATED — remove white background
        self.sim_text.config(bg="#dbe9ff", fg="black", insertbackground="black")

        mid = ttk.Frame(self.tab_sim)
        mid.pack(fill="both",expand=True,padx=8,pady=6)

        left = ttk.Frame(mid)
        left.pack(side="left",fill="both",expand=True)
        ttk.Label(left,text="Last 10 Categorized Entries:", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        self.cat_listbox = tk.Listbox(left, selectmode="browse", font=("Consolas", 10))
        self.cat_listbox.pack(fill="both",expand=True, padx=(0,6), side="left")
        
# UPDATED — fix white background
        self.cat_listbox.config(bg="#dbe9ff", fg="black")

        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.cat_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.cat_listbox.config(yscrollcommand=scrollbar.set)

        right = ttk.Frame(mid, width=320)
        right.pack(side="right", fill="y")
        ttk.Button(right,text="Export CSV",command=self.export_csv).pack(fill="x", pady=(0,6))
        ttk.Button(right,text="Save Raw Log",command=self.save_raw_log).pack(fill="x", pady=(0,6))
        ttk.Button(right,text="Open Logs Folder",command=lambda: os.startfile(str(LOG_DIR))).pack(fill="x", pady=(0,6))

        self.update_preview_loop()

    def process_sim_input(self):
        text = self.sim_text.get("1.0",tk.END).strip()
        
        if not text:
            messagebox.showinfo("No input","Enter some simulated input")
            return
        window_title = "Simulated Window"
        for line in text.splitlines():
            cat, value = categorize_line(line, window_title)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            append_sim_log(line)
            append_csv_row(timestamp, window_title, line, cat)
        self.update_preview_listbox()
        notify("VKDDS Simulation","Input processed successfully")

    def generate_test_data(self):
        sample = """user: admin
pass: admin123
email: test@example.com
https://www.google.com
Hello this is a chat conversation
"""
        self.sim_text.insert("end", sample)

    def update_preview_listbox(self):
        self.cat_listbox.delete(0,tk.END)
        if not SIM_LOG_FILE.exists(): return
        lines = SIM_LOG_FILE.read_text(encoding="utf-8").splitlines()[-10:]
        for l in lines:
            cat,_ = categorize_line(l)
            self.cat_listbox.insert("end", f"[{cat}] {l}")

    def update_preview_loop(self):
        self.update_preview_listbox()
        self.root.after(4000, self.update_preview_loop)

    def export_csv(self):
        if not CSV_LOG_FILE.exists():
            messagebox.showinfo("Export CSV","No CSV file exists yet")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialdir=LOG_DIR, filetypes=[("CSV","*.csv")])
        if not path: return
        import shutil
        shutil.copy(CSV_LOG_FILE,path)
        messagebox.showinfo("Exported",f"CSV exported to {path}")

    def save_raw_log(self):
        if not SIM_LOG_FILE.exists():
            messagebox.showinfo("Save Raw Log","No simulated log exists yet")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialdir=LOG_DIR, filetypes=[("Text","*.txt")])
        if not path: return
        import shutil
        shutil.copy(SIM_LOG_FILE,path)
        messagebox.showinfo("Saved",f"Raw log saved to {path}")

    # ----------------- Email Tab -----------------
    def setup_email_tab(self):
        frame = ttk.Frame(self.tab_email, padding=8)
        frame.pack(fill="both",expand=True)
        ttk.Checkbutton(frame, text="Enable Email Alerts", variable=self.email_enabled_var, command=self.toggle_email).pack(anchor="w")
        ttk.Label(frame,text="SMTP Server:").pack(anchor="w", pady=(6,0))
        self.smtp_entry = ttk.Entry(frame)
        self.smtp_entry.pack(fill="x")
        self.smtp_entry.insert(0, EMAIL_SMTP)
        ttk.Label(frame,text="Port:").pack(anchor="w", pady=(6,0))
        self.port_entry = ttk.Entry(frame)
        self.port_entry.pack(fill="x")
        self.port_entry.insert(0, str(EMAIL_PORT))
        ttk.Label(frame,text="Sender Email:").pack(anchor="w", pady=(6,0))
        self.sender_entry = ttk.Entry(frame)
        self.sender_entry.pack(fill="x")
        self.sender_entry.insert(0, EMAIL_USER)
        ttk.Label(frame,text="App Password:").pack(anchor="w", pady=(6,0))
        self.pass_entry = ttk.Entry(frame, show="*")
        self.pass_entry.pack(fill="x")
        self.pass_entry.insert(0, EMAIL_APP_PASSWORD)
        ttk.Label(frame,text="Receiver Email:").pack(anchor="w", pady=(6,0))
        self.recv_entry = ttk.Entry(frame)
        self.recv_entry.pack(fill="x")
        self.recv_entry.insert(0, EMAIL_TO)
        ttk.Button(frame,text="Send Test Email (CSV)", command=lambda:self.send_test_email(csv=True)).pack(pady=(12,0))
        ttk.Button(frame,text="Send Test Email (Raw Log)", command=lambda:self.send_test_email(csv=False)).pack(pady=(6,0))
        ttk.Label(frame,text="Last 10 Email Preview Lines:").pack(anchor="w", pady=(12,0))
        self.email_preview = tk.Listbox(frame)
        self.email_preview.pack(fill="both", expand=True)
        
# UPDATED — fix white background
        self.email_preview.config(bg="#dbe9ff", fg="black")

        # scrollbar for email_preview
        scrollbar_email = ttk.Scrollbar(frame, orient="vertical", command=self.email_preview.yview)
        scrollbar_email.pack(side="right", fill="y")
        self.email_preview.config(yscrollcommand=scrollbar_email.set)
        self.update_email_preview_loop()

    def toggle_email(self):
        global EMAIL_ENABLED
        EMAIL_ENABLED = self.email_enabled_var.get()

    def send_test_email(self, csv=True):
        self.update_email_settings()
        path = CSV_LOG_FILE if csv else SIM_LOG_FILE
        if not path.exists():
            messagebox.showinfo("Email Test", "No file to send.")
            return
        ok,msg = send_email(subject=f"VKDDS Test Email ({'CSV' if csv else 'Raw'})",
                            body="This is a test email from VKDDS safe simulation.",
                            attachment_path=path)
        messagebox.showinfo("Email Test", f"Email status: {msg}")
        self.update_email_preview_list(path)

    def update_email_settings(self):
        global EMAIL_SMTP, EMAIL_PORT, EMAIL_USER, EMAIL_APP_PASSWORD, EMAIL_TO
        EMAIL_SMTP = self.smtp_entry.get()
        EMAIL_PORT = int(self.port_entry.get())
        EMAIL_USER = self.sender_entry.get()
        EMAIL_APP_PASSWORD = self.pass_entry.get()
        EMAIL_TO = self.recv_entry.get()

    def update_email_preview_list(self, path=None):
        self.email_preview.delete(0, tk.END)
        if path and path.exists():
            with open(path,"r",encoding="utf-8") as f:
                lines = f.readlines()[-10:]
            for l in lines:
                self.email_preview.insert(tk.END, l.strip())

    def update_email_preview_loop(self):
        self.update_email_preview_list(SIM_LOG_FILE)
        self.root.after(5000, self.update_email_preview_loop)

# ---------------------------
# Main
# ---------------------------
if __name__=="__main__":
    root = tk.Tk()
    app = VKDDSApp(root)
    root.mainloop()
