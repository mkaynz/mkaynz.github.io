---
layout: default
---


# Static Analysis Demo

<p>In this demo, I performed static malware analysis on a keylogger executable and Python script to identify its functionality and potential threats without executing it. By extracting metadata, analyzing embedded strings, and verifying hashes against threat intelligence databases, I uncovered key indicators of compromise (IOCs) and assessed the malware’s behavior. </br>
Key Steps:

Keylogger Creation & Analysis: Developed a basic keylogger to understand how malicious keylogging software is structured.

Executable & Python Script Analysis: Examined PE headers and imports.

Hash Analysis: Generated MD5, SHA-256 hashes and cross-referenced them with open-source threat intelligence platforms (VirusTotal).

Embedded String Extraction: Used strings analysis to uncover potential file paths.

Threat Intelligence Correlation: Checked the MD5 hash in public databases to see if it matched any known malware signatures. </br>
Key Takeaways:

Identified static indicators of a keylogger.

Demonstrated low-risk malware analysis techniques that can be applied in real-world security operations.

Validated findings using open-source intelligence (OSINT) tools to strengthen detection capabilities.

Navigate to the below link for the full walk-through.
[Static Analysis Demo](https://youtu.be/vjDuOHOMlJc?si=TqcFx6O982eB3LV_) </p>

## Dynamic Analysis Demo

<p>In this demo, I performed dynamic malware analysis on a keylogger executable and Python script, observing its real-time behavior in a sandboxed environment while also testing its ability to bypass Windows Defender and built-in security mechanisms. This included analyzing process execution, file system modifications, network activity, and anti-virus evasion techniques.

Key Steps:

Safe Execution Environment: Deployed the malware in an isolated virtual machine to prevent host system compromise.
Windows Defender Evasion: Obfuscated the script/executable to avoid signature-based detection.
Used custom packing techniques to prevent AV detection. 
Tested execution against Windows Defender and noted bypassed security alerts. 
Keylogging Behavior Analysis: Verified that the malware successfully captured keystrokes and logged them without detection.

Key Takeaways:

Successfully bypassed Windows Defender using obfuscation and packing techniques.

Demonstrated how keyloggers operate dynamically, confirming findings from static analysis.

Identified key persistence mechanisms and stealth techniques used by malware.

Gained hands-on experience in behavior-based malware detection and defense evasion tactics.

Navigate to the below link for the full walk-through.

[Dynamic Analysis Demo](https://youtu.be/RvHy83w9o5A?si=A4rtUoZElggDOkA1) </p>
### Header 3



