import yara
import os

# Define some basic rules to detect suspicious files
# In a real app, you would load these from a .yar file
RULES_SOURCE = """
rule Suspicious_Strings {
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "keylogger" nocase
        $d = "bitcoin" nocase
    condition:
        2 of them
}

rule Fake_PDF {
    meta:
        description = "Detects EXE files disguised as PDF"
    strings:
        $mz = "MZ" // Executable header
    condition:
        $mz at 0 and filename matches /\.pdf$/is
}
"""

def compile_rules():
    try:
        return yara.compile(source=RULES_SOURCE)
    except Exception as e:
        print(f"YARA Error: {e}")
        return None

def scan_file_with_yara(file_path):
    rules = compile_rules()
    if not rules:
        return "⚠ Error: YARA Engine Failed"

    try:
        matches = rules.match(file_path)
        if matches:
            # Get the names of the rules that matched
            threats = [match.rule for match in matches]
            return f"⚠ THREAT DETECTED: {', '.join(threats)}"
        else:
            return "✔ Clean (No YARA matches)"
    except Exception as e:
        return f"Error scanning: {str(e)}"