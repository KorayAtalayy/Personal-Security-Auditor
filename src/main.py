
#DUTİES 2.WEEK:Scanning FİREWALL,Makes Report

import platform
import ctypes
import datetime
import sys
import subprocess  # <-- NEWLY ADDED! (To execute Windows commands)

def print_banner():
    # Shows the project name and scan time
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print("   INTERNAL SECURITY BASELINE CHECKER (v2.0) - Week 2")
    print(f"   Scan Date: {current_time}")
    print("=" * 60)

def check_os():
    # Identifies the operating system
    os_name = platform.system()
    print(f"[INFO] Detected OS: {os_name}")
    
    if os_name != "Windows":
        print("[ERROR] This tool is designed for Windows only.")
        return False
    return True

def is_admin():
    # Checks if the user running the script has Administrator rights
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("[OK] User Privilege: ADMINISTRATOR (Great!)")
            return True
        else:
            print("[WARNING] User Privilege: STANDARD USER")
            print("   -> Some deep security checks might fail without Admin rights.")
            return False
    except:
        print("[ERROR] Could not check privileges.")
        return False

# --- NEWLY ADDED SECURITY CHECK (WEEK 2) ---
def check_firewall():
    print("\n[INFO] Checking Windows Firewall status...")
    try:
        # Running the 'netsh' command to get firewall profile states
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, check=True
        )
        
        output = result.stdout.lower()
        
        # Checking if the firewall state is 'on'
        if "state" in output and "on" in output:
            print("[OK] Firewall is ENABLED. (Secure)")
        else:
            print("[WARNING] Firewall might be DISABLED or partially off! (Risk)")
            
    except Exception as e:
        print(f"[ERROR] Could not check firewall. Details: {e}")

def check_usb_policies():
    print("\n[INFO] Checking AutoRun & AutoPlay Policies (USB Security)...")
    try:
        from scanners import usb_scanner
        results = usb_scanner.scan_all()
        
        # Display AutoRun status
        ar = results["autorun"]
        print(f"\n--- AutoRun Policy Check ---")
        print(f"Status: {ar['status']}")
        print(f"Active Value: {ar['value']}")
        print(f"Active Source: {ar['source']}")
        print(f"Risk Level: {ar['risk']}")
        if ar["status"] == "OK":
            print(f"[OK] {ar['message']}")
        else:
            print(f"[WARNING] {ar['message']}")
            
        # Display AutoPlay status
        ap = results["autoplay"]
        print(f"\n--- AutoPlay Policy Check ---")
        print(f"Status: {ap['status']}")
        print(f"Active Value: {ap['value']}")
        print(f"Active Source: {ap['source']}")
        print(f"Risk Level: {ap['risk']}")
        if ap["status"] == "OK":
            print(f"[OK] {ap['message']}")
        else:
            print(f"[WARNING] {ap['message']}")
            
    except Exception as e:
        print(f"[ERROR] Could not check AutoRun/AutoPlay. Details: {e}")

# --- MAIN PROGRAM EXECUTION ---
if __name__ == "__main__":
    print_banner()      
    
    # Proceed with security checks only if the OS is Windows
    if check_os():          
        is_admin()          
        check_firewall()  # <-- WEEK 2 TASK RUNS HERE!
        check_usb_policies()  # <-- USB REGISTRY AUDIT RUNS HERE!
    
    print("\n" + "=" * 60)
    print("   SCAN COMPLETED.")
    print("=" * 60)
