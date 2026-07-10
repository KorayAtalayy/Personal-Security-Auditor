def scan_firewall():
    """
    Checks the status of the Windows Firewall by executing the 'netsh' command.
    Returns a status dictionary with risk and message.
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, check=True
        )
        output = result.stdout.lower()
        
        # In a fully secure setup, all profile states should be ON
        # The output contains "State ON" for each profile (domain, private, public)
        # If any profile has "state off" or isn't on, we want to warn.
        if "state" in output:
            # Let's count how many profiles are ON vs OFF
            # Standard output contains sections like:
            # Domain Profile Settings:
            # State                                 ON
            # Private Profile Settings:
            # State                                 ON
            # Public Profile Settings:
            # State                                 ON
            
            if "off" in output:
                return {
                    "status": "WARNING",
                    "value": "Disabled / Partially Off",
                    "source": "Windows Advanced Firewall",
                    "risk": "HIGH",
                    "message": "Windows Firewall is disabled on at least one network profile. This exposes your system to external network threats."
                }
            elif "on" in output:
                return {
                    "status": "OK",
                    "value": "Enabled (All Profiles)",
                    "source": "Windows Advanced Firewall",
                    "risk": "LOW",
                    "message": "Windows Firewall is enabled for all network profiles (Domain, Private, Public). (Secure)"
                }
            
        return {
            "status": "WARNING",
            "value": "Unknown State",
            "source": "Windows Advanced Firewall",
            "risk": "MEDIUM",
            "message": "Could not determine precise firewall status from netsh output. Please check manually."
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "value": "Scan Failed",
            "source": "Windows Advanced Firewall",
            "risk": "HIGH",
            "message": f"Could not check firewall status. Error: {e}"
        }
