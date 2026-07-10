import winreg
import sys

def read_reg_value(hive, subkey, value_name):
    """
    Safely reads a registry value.
    Returns (value, value_type) if found, otherwise (None, None).
    """
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            val, val_type = winreg.QueryValueEx(key, value_name)
            return val, val_type
    except FileNotFoundError:
        return None, None
    except PermissionError:
        return "PERMISSION_DENIED", None
    except Exception:
        return None, None

def check_autorun():
    """
    Audits the NoDriveTypeAutoRun registry setting.
    Prioritizes:
      1. HKLM Policy (GPO)
      2. HKCU Policy (GPO)
      3. HKLM Standard
      4. HKCU Standard
    Default Windows behavior is 0x91 (145) or 0x95 if unset, which enables AutoRun on USB drives.
    Secure configuration is 0xFF (255) to disable AutoRun on all drive types.
    """
    paths = [
        {"hive": winreg.HKEY_LOCAL_MACHINE, "name": "HKLM (Policy)", "subkey": r"Software\Policies\Microsoft\Windows\Explorer"},
        {"hive": winreg.HKEY_CURRENT_USER, "name": "HKCU (Policy)", "subkey": r"Software\Policies\Microsoft\Windows\Explorer"},
        {"hive": winreg.HKEY_LOCAL_MACHINE, "name": "HKLM (Standard)", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"},
        {"hive": winreg.HKEY_CURRENT_USER, "name": "HKCU (Standard)", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"},
    ]
    
    active_val = None
    active_source = None
    
    for p in paths:
        val, val_type = read_reg_value(p["hive"], p["subkey"], "NoDriveTypeAutoRun")
        if val == "PERMISSION_DENIED":
            # Keep searching, but note permission issue
            continue
        if val is not None:
            active_val = val
            active_source = p["name"]
            break
            
    # Resolve vulnerability
    if active_val is None:
        # Default behavior: usually 0x91 (145), meaning AutoRun is enabled for USBs (Removable drives)
        return {
            "status": "WARNING",
            "value": "Not Configured (Default)",
            "source": "Windows Defaults",
            "risk": "HIGH",
            "message": "AutoRun is using default Windows settings (0x91/0x95). USB drives can execute programs automatically, which poses a malware execution risk."
        }
        
    try:
        val_int = int(active_val)
        if val_int == 255 or val_int == 0xFF:
            return {
                "status": "OK",
                "value": f"{hex(val_int)} ({val_int})",
                "source": active_source,
                "risk": "LOW",
                "message": "AutoRun is fully disabled on all drive types. (Secure)"
            }
        else:
            return {
                "status": "WARNING",
                "value": f"{hex(val_int)} ({val_int})",
                "source": active_source,
                "risk": "MEDIUM",
                "message": f"AutoRun is partially enabled (active: {active_source}). It should ideally be set to 0xFF (255) to disable AutoRun on all drives."
            }
    except ValueError:
        return {
            "status": "WARNING",
            "value": str(active_val),
            "source": active_source,
            "risk": "MEDIUM",
            "message": "AutoRun value is configured but has an invalid data format."
        }

def check_autoplay():
    """
    Audits the DisableAutoplay registry setting.
    Prioritizes:
      1. HKLM Policy (GPO)
      2. HKCU Policy (GPO)
      3. HKLM Standard
      4. HKCU Standard
    DisableAutoplay = 1 means AutoPlay is disabled (Secure).
    DisableAutoplay = 0 (or unset) means AutoPlay is enabled (Insecure).
    """
    paths = [
        {"hive": winreg.HKEY_LOCAL_MACHINE, "name": "HKLM (Policy)", "subkey": r"Software\Policies\Microsoft\Windows\Explorer"},
        {"hive": winreg.HKEY_CURRENT_USER, "name": "HKCU (Policy)", "subkey": r"Software\Policies\Microsoft\Windows\Explorer"},
        {"hive": winreg.HKEY_LOCAL_MACHINE, "name": "HKLM (Standard)", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"},
        {"hive": winreg.HKEY_CURRENT_USER, "name": "HKCU (Standard)", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"},
    ]
    
    active_val = None
    active_source = None
    
    for p in paths:
        val, val_type = read_reg_value(p["hive"], p["subkey"], "DisableAutoplay")
        if val == "PERMISSION_DENIED":
            continue
        if val is not None:
            active_val = val
            active_source = p["name"]
            break
            
    if active_val is None:
        return {
            "status": "WARNING",
            "value": "Not Configured (Default)",
            "source": "Windows Defaults",
            "risk": "MEDIUM",
            "message": "AutoPlay is enabled by default. Connected media files/drives can trigger prompts and actions automatically."
        }
        
    try:
        val_int = int(active_val)
        if val_int == 1:
            return {
                "status": "OK",
                "value": "1 (Disabled)",
                "source": active_source,
                "risk": "LOW",
                "message": "AutoPlay is completely disabled. (Secure)"
            }
        else:
            return {
                "status": "WARNING",
                "value": "0 (Enabled)",
                "source": active_source,
                "risk": "MEDIUM",
                "message": f"AutoPlay is explicitly enabled (active: {active_source}). Connected drives will trigger autoplay prompts or actions."
            }
    except ValueError:
        return {
            "status": "WARNING",
            "value": str(active_val),
            "source": active_source,
            "risk": "MEDIUM",
            "message": "AutoPlay setting is configured but has an invalid data format."
        }

def scan_all():
    """
    Runs both AutoRun and AutoPlay audits.
    """
    return {
        "autorun": check_autorun(),
        "autoplay": check_autoplay()
    }

