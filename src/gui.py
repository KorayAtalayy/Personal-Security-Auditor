import os
import sys
import datetime
import platform
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Dynamically adjust path to allow clean imports of scanners
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import our scanner modules
try:
    from scanners import firewall_scanner
    from scanners import usb_scanner
except ImportError:
    # If run inside the src folder directly
    import firewall_scanner
    import usb_scanner

class SecurityAuditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Internal Security Baseline Checker (GUI v1.0)")
        self.root.geometry("850x680")
        self.root.minsize(800, 600)
        
        # Color Palette - Catppuccin Mocha inspired Dark Theme
        self.bg_color = "#1e1e2e"          # Base background
        self.card_bg = "#252538"           # Card background
        self.fg_color = "#cdd6f4"          # Text color
        self.fg_dim = "#a6adc8"            # Dimmed text color
        self.accent_color = "#89b4fa"      # Blue accent
        self.accent_hover = "#b4befe"      # Lavender hover
        self.btn_bg = "#313244"            # Button background
        
        # Status Colors
        self.color_ok = "#a6e3a1"          # Soft Green
        self.color_warning = "#f9e2af"     # Soft Yellow
        self.color_danger = "#f38ba8"      # Soft Red
        self.color_info = "#89dceb"        # Light Blue

        # Config Styles
        self.setup_styles()
        
        # Store scan results
        self.scan_results = None
        self.is_admin_user = self.check_admin_status()
        
        # Create Layout
        self.create_widgets()
        
    def setup_styles(self):
        self.root.configure(bg=self.bg_color)
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure standard ttk styles
        self.style.configure(".", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        
        # Buttons
        self.style.configure("Accent.TButton", 
                             background=self.accent_color, 
                             foreground=self.bg_color, 
                             font=("Segoe UI", 10, "bold"), 
                             borderwidth=0, 
                             focuscolor=self.accent_color)
        self.style.map("Accent.TButton", 
                       background=[("active", self.accent_hover), ("disabled", "#45475a")],
                       foreground=[("disabled", "#585b70")])
        
        self.style.configure("Standard.TButton", 
                             background=self.btn_bg, 
                             foreground=self.fg_color, 
                             font=("Segoe UI", 10), 
                             borderwidth=0)
        self.style.map("Standard.TButton", 
                       background=[("active", "#45475a"), ("disabled", "#181825")])

    def check_admin_status(self):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except:
            return False

    def create_widgets(self):
        # --- Top Header Frame ---
        header_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=15)
        header_frame.pack(fill="x")
        
        title_label = tk.Label(header_frame, 
                               text="INTERNAL SECURITY BASELINE CHECKER", 
                               font=("Segoe UI", 16, "bold"), 
                               bg=self.bg_color, 
                               fg=self.accent_color)
        title_label.pack(anchor="w")
        
        # Sub-header with system info
        os_info = f"OS: Windows ({platform.release()})"
        priv_text = "ADMINISTRATOR" if self.is_admin_user else "STANDARD USER"
        priv_color = self.color_ok if self.is_admin_user else self.color_warning
        
        info_frame = tk.Frame(header_frame, bg=self.bg_color)
        info_frame.pack(fill="x", pady=(5, 0))
        
        tk.Label(info_frame, text=os_info, font=("Segoe UI", 9), bg=self.bg_color, fg=self.fg_dim).pack(side="left")
        tk.Label(info_frame, text="  |  Privilege: ", font=("Segoe UI", 9), bg=self.bg_color, fg=self.fg_dim).pack(side="left")
        self.priv_badge = tk.Label(info_frame, text=priv_text, font=("Segoe UI", 9, "bold"), bg=self.bg_color, fg=priv_color)
        self.priv_badge.pack(side="left")
        
        if not self.is_admin_user:
            tk.Label(info_frame, 
                     text="  (Some advanced checks require admin rights)", 
                     font=("Segoe UI", 9, "italic"), 
                     bg=self.bg_color, 
                     fg=self.color_warning).pack(side="left")

        # Separator line
        sep = tk.Frame(self.root, height=1, bg="#313244")
        sep.pack(fill="x", padx=20)
        
        # --- Main Layout Body ---
        body_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=15)
        body_frame.pack(fill="both", expand=True)

        # Control Panel (Buttons)
        controls_frame = tk.Frame(body_frame, bg=self.bg_color)
        controls_frame.pack(fill="x", pady=(0, 15))
        
        self.scan_btn = ttk.Button(controls_frame, text="Run Security Audit", style="Accent.TButton", command=self.run_audit)
        self.scan_btn.pack(side="left", padx=(0, 10))
        
        self.export_btn = ttk.Button(controls_frame, text="Export Audit Report", style="Standard.TButton", command=self.export_report, state="disabled")
        self.export_btn.pack(side="left")
        
        self.status_lbl = tk.Label(controls_frame, text="Ready to audit.", font=("Segoe UI", 9, "italic"), bg=self.bg_color, fg=self.fg_dim)
        self.status_lbl.pack(side="right", pady=5)

        # Dashboard Grid for Cards (3 columns)
        grid_frame = tk.Frame(body_frame, bg=self.bg_color)
        grid_frame.pack(fill="x", pady=(0, 15))
        grid_frame.columnconfigure((0, 1, 2), weight=1, uniform="equal")

        # Card 1: Windows Firewall
        self.card_fw = self.create_card(grid_frame, "Windows Firewall", 0)
        # Card 2: AutoRun Policies
        self.card_ar = self.create_card(grid_frame, "AutoRun Policies", 1)
        # Card 3: AutoPlay Policies
        self.card_ap = self.create_card(grid_frame, "AutoPlay Policies", 2)

        # --- Detailed Audit Log Terminal ---
        log_frame = tk.LabelFrame(body_frame, 
                                  text=" Detailed Security Log & Recommendations ", 
                                  bg=self.bg_color, 
                                  fg=self.fg_dim, 
                                  font=("Segoe UI", 9, "bold"), 
                                  padx=10, 
                                  pady=10)
        log_frame.pack(fill="both", expand=True)
        
        # Scrollbar and Text Widget
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.log_txt = tk.Text(log_frame, 
                               bg="#11111b", 
                               fg="#a6e3a1", 
                               insertbackground="white", 
                               font=("Consolas", 10), 
                               borderwidth=0, 
                               yscrollcommand=scrollbar.set)
        self.log_txt.pack(fill="both", expand=True)
        scrollbar.config(command=self.log_txt.yview)
        
        # Initial text prompt
        self.log_txt.insert("1.0", "System idle. Click 'Run Security Audit' to begin local vulnerability scanning...\n")
        self.log_txt.config(state="disabled")

    def create_card(self, parent, title, col):
        card = tk.Frame(parent, bg=self.card_bg, padx=15, pady=15, highlightthickness=1, highlightbackground="#313244")
        card.grid(row=0, column=col, padx=5, sticky="nsew")
        
        # Title
        lbl_title = tk.Label(card, text=title, font=("Segoe UI", 11, "bold"), bg=self.card_bg, fg=self.fg_color)
        lbl_title.pack(anchor="w", pady=(0, 5))
        
        # Value Badge
        lbl_val = tk.Label(card, text="NOT SCANNED", font=("Segoe UI", 10, "bold"), bg="#313244", fg=self.fg_dim, padx=8, pady=3)
        lbl_val.pack(anchor="w", pady=(0, 8))
        
        # Summary/Status Text
        lbl_msg = tk.Label(card, text="Run scan to check state.", font=("Segoe UI", 9), bg=self.card_bg, fg=self.fg_dim, wraplength=200, justify="left")
        lbl_msg.pack(anchor="w", fill="both", expand=True)
        
        return {"frame": card, "val": lbl_val, "msg": lbl_msg}

    def update_card(self, card_dict, status, value, message):
        # Map statuses to colors
        if status == "OK":
            bg_color = "#2e3f35"  # Soft dark green
            fg_color = self.color_ok
        elif status == "WARNING":
            bg_color = "#3f3c2c"  # Soft dark yellow
            fg_color = self.color_warning
        elif status == "ERROR":
            bg_color = "#3f2e2e"  # Soft dark red
            fg_color = self.color_danger
        else:
            bg_color = "#313244"
            fg_color = self.fg_dim
            
        card_dict["val"].config(text=value.upper(), bg=bg_color, fg=fg_color)
        card_dict["msg"].config(text=message, fg=self.fg_color)

    def write_log(self, text, tag=None):
        self.log_txt.config(state="normal")
        if tag:
            self.log_txt.insert("end", text, tag)
        else:
            self.log_txt.insert("end", text)
        self.log_txt.see("end")
        self.log_txt.config(state="disabled")

    def run_audit(self):
        self.scan_btn.config(state="disabled")
        self.status_lbl.config(text="Scanning system state...")
        self.root.update_idletasks()
        
        # Clear log textbox
        self.log_txt.config(state="normal")
        self.log_txt.delete("1.0", "end")
        
        # Setup font coloring tags in text widget
        self.log_txt.tag_config("ok", foreground=self.color_ok)
        self.log_txt.tag_config("warn", foreground=self.color_warning)
        self.log_txt.tag_config("danger", foreground=self.color_danger)
        self.log_txt.tag_config("info", foreground=self.accent_color)
        self.log_txt.tag_config("dim", foreground=self.fg_dim)
        
        self.log_txt.config(state="disabled")

        # Timestamp
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.write_log(f"==========================================================\n", "dim")
        self.write_log(f"   INTERNAL SECURITY BASELINE AUDIT - SCAN LOG\n", "info")
        self.write_log(f"   Scan Date: {scan_time}\n", "dim")
        self.write_log(f"==========================================================\n\n", "dim")
        
        # 1. OS & Privileges logs
        self.write_log(f"[INFO] Operating System: {platform.system()} {platform.release()}\n")
        if self.is_admin_user:
            self.write_log(f"[OK] Privilege Level: ADMINISTRATOR (Full scans enabled)\n", "ok")
        else:
            self.write_log(f"[WARN] Privilege Level: STANDARD USER\n", "warn")
            self.write_log("       -> Deep scans or command executions may be limited.\n", "dim")
            
        # 2. Run Firewall Scanner
        self.write_log("\n[RUN] Auditing Windows Advanced Firewall status...\n", "info")
        try:
            fw_res = firewall_scanner.scan_firewall()
            self.update_card(self.card_fw, fw_res["status"], fw_res["value"], fw_res["message"])
            
            log_tag = "ok" if fw_res["status"] == "OK" else "warn"
            self.write_log(f"[{fw_res['status']}] Firewall Audit completed.\n", log_tag)
            self.write_log(f"      Active Value:  {fw_res['value']}\n", "dim")
            self.write_log(f"      Risk Level:    {fw_res['risk']}\n", "dim")
            self.write_log(f"      Assessment:    {fw_res['message']}\n", log_tag)
        except Exception as e:
            self.update_card(self.card_fw, "ERROR", "Scan Failed", str(e))
            self.write_log(f"[ERROR] Firewall scan encountered error: {e}\n", "danger")
            fw_res = {"status": "ERROR", "value": "Scan Failed", "message": str(e), "risk": "HIGH"}

        # 3. Run USB Registries Scanner
        self.write_log("\n[RUN] Auditing USB AutoRun & AutoPlay configurations...\n", "info")
        try:
            usb_res = usb_scanner.scan_all()
            
            # AutoRun Card
            ar = usb_res["autorun"]
            self.update_card(self.card_ar, ar["status"], ar["value"], ar["message"])
            ar_tag = "ok" if ar["status"] == "OK" else "warn"
            self.write_log(f"[{ar['status']}] AutoRun Policy Check:\n", ar_tag)
            self.write_log(f"      Active Value:  {ar['value']}\n", "dim")
            self.write_log(f"      Source Hive:   {ar['source']}\n", "dim")
            self.write_log(f"      Risk Level:    {ar['risk']}\n", "dim")
            self.write_log(f"      Assessment:    {ar['message']}\n", ar_tag)
            
            # AutoPlay Card
            ap = usb_res["autoplay"]
            self.update_card(self.card_ap, ap["status"], ap["value"], ap["message"])
            ap_tag = "ok" if ap["status"] == "OK" else "warn"
            self.write_log(f"\n[{ap['status']}] AutoPlay Policy Check:\n", ap_tag)
            self.write_log(f"      Active Value:  {ap['value']}\n", "dim")
            self.write_log(f"      Source Hive:   {ap['source']}\n", "dim")
            self.write_log(f"      Risk Level:    {ap['risk']}\n", "dim")
            self.write_log(f"      Assessment:    {ap['message']}\n", ap_tag)
            
        except Exception as e:
            self.update_card(self.card_ar, "ERROR", "Scan Failed", str(e))
            self.update_card(self.card_ap, "ERROR", "Scan Failed", str(e))
            self.write_log(f"[ERROR] USB policy scan encountered error: {e}\n", "danger")
            usb_res = {
                "autorun": {"status": "ERROR", "value": "Scan Failed", "message": str(e), "risk": "HIGH", "source": "ERROR"},
                "autoplay": {"status": "ERROR", "value": "Scan Failed", "message": str(e), "risk": "HIGH", "source": "ERROR"}
            }

        # Scan Complete
        self.write_log(f"\n==========================================================\n", "dim")
        self.write_log(f"   SCAN COMPLETED SUCCESSFULLY.\n", "ok")
        self.write_log(f"==========================================================\n", "dim")
        
        # Save scan results for exporting
        self.scan_results = {
            "time": scan_time,
            "firewall": fw_res,
            "autorun": usb_res["autorun"],
            "autoplay": usb_res["autoplay"]
        }
        
        self.scan_btn.config(state="normal")
        self.export_btn.config(state="normal")
        self.status_lbl.config(text="Scan completed.")

    def export_report(self):
        if not self.scan_results:
            messagebox.showerror("Error", "No scan results available to export. Run a scan first.")
            return
            
        # Target directory inside project: reports/
        reports_dir = os.path.join(os.path.dirname(current_dir), "reports")
        if not os.path.exists(reports_dir):
            try:
                os.makedirs(reports_dir)
            except:
                reports_dir = os.path.dirname(current_dir) # fallback to project root

        # Generate default filename
        file_timestamp = self.scan_results["time"].replace(":", "-").replace(" ", "_")
        default_filename = f"security_report_{file_timestamp}.txt"
        
        filepath = filedialog.asksaveasfilename(
            initialdir=reports_dir,
            initialfile=default_filename,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Security Audit Report"
        )
        
        if not filepath:
            return # User cancelled

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write(f"   INTERNAL SECURITY BASELINE AUDIT REPORT\n")
                f.write(f"   Generated on: {self.scan_results['time']}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("1. OS & ENVIRONMENT INFORMATION\n")
                f.write(f"   Operating System: {platform.system()} {platform.release()}\n")
                f.write(f"   Privilege Level:  {'ADMINISTRATOR (Full Rights)' if self.is_admin_user else 'STANDARD USER (Restricted)'}\n\n")
                
                f.write("2. FIREWALL AUDIT RESULTS\n")
                fw = self.scan_results["firewall"]
                f.write(f"   Status:        {fw['status']}\n")
                f.write(f"   Active Value:  {fw['value']}\n")
                f.write(f"   Risk Rating:   {fw['risk']}\n")
                f.write(f"   Details:       {fw['message']}\n\n")
                
                f.write("3. USB POLICY AUDIT RESULTS\n")
                ar = self.scan_results["autorun"]
                f.write(f"   - AutoRun Status:     {ar['status']}\n")
                f.write(f"     Active Value:       {ar['value']}\n")
                f.write(f"     Source Registry:    {ar['source']}\n")
                f.write(f"     Risk Rating:        {ar['risk']}\n")
                f.write(f"     Details:            {ar['message']}\n\n")
                
                ap = self.scan_results["autoplay"]
                f.write(f"   - AutoPlay Status:    {ap['status']}\n")
                f.write(f"     Active Value:       {ap['value']}\n")
                f.write(f"     Source Registry:    {ap['source']}\n")
                f.write(f"     Risk Rating:        {ap['risk']}\n")
                f.write(f"     Details:            {ap['message']}\n\n")
                
                f.write("=" * 60 + "\n")
                f.write("   END OF REPORT\n")
                f.write("=" * 60 + "\n")
                
            messagebox.showinfo("Report Exported", f"Security report successfully saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write report to file. Error: {e}")

if __name__ == "__main__":
    # Ensure standard DPI scaling on high DPI screens
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except:
            pass
            
    root = tk.Tk()
    app = SecurityAuditorApp(root)
    root.mainloop()
