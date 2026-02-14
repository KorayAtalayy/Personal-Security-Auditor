#DUTİES:OS IDENTİFİCATİON(SİSTEM TANIMA),PRİVİLAGE CHECK(EN ÜST YETKİ KONTRÖLÜ),TİMESTAMPİNG(ZAMAN DAMGASI)

import platform
import ctypes
import datetime
import sys

def print_banner():
    # Shows the project name and time
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print("   INTERNAL SECURITY BASELINE CHECKER (v1.0)")
    print(f"   Scan Date: {current_time}")
    print("=" * 60)

def check_os():
    # Checks if we are on Windows
    os_name = platform.system()
    print(f"[INFO] Detected OS: {os_name}")
    
    if os_name != "Windows":
        print("[ERROR] This tool is designed for Windows only.")
        return False
    return True

def is_admin():
    # Checks for Administrator privileges
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("[OK] User Privilege: ADMINISTRATOR (Great!)")
        else:
            print("[WARNING] User Privilege: STANDARD USER")
            print("   -> You should run this as Administrator for full scan.")
    except:
        print("[ERROR] Could not check privileges.")

# --- MAIN PROGRAM STARTS HERE ---
if __name__ == "__main__":
    print_banner()      
    check_os()          
    is_admin()          
    
    print("\n" + "=" * 60)
    print("   SCAN COMPLETED.")
    print("=" * 60)
