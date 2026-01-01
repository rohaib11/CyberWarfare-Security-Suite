import requests
import hashlib

def check_email_leak(email):
    """
    Checks the 'Have I Been Pwned' API.
    Note: The full API requires a paid key, but we can simulate the check 
    or use the free 'breachedaccount' endpoint if available, 
    or use a public lookup logic.
    
    For this student project, we will use a logic that simulates a check 
    or uses a free lookup if available. 
    """
    # OPTION A: If you have an API Key (Real Check)
    # url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    # headers = {"hibp-api-key": "YOUR_KEY"}
    
    # OPTION B: Simulation (For Portfolio/Demo purposes without paying)
    # We will simulate a "Breach Check" delay and result.
    
    import time
    time.sleep(1) # Simulate network request
    
    # Fake list of "hacked" emails for testing
    demo_hacked_emails = ["test@example.com", "admin@admin.com", "hacked@user.com"]
    
    if email in demo_hacked_emails:
        return "⚠ ALERT: This email was found in 3 Data Breaches! (Adobe, LinkedIn, Canva)"
    
    return "✔ CLEAN: No leaks found for this email."