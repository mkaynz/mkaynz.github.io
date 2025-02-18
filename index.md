---
layout: default
---

# Deploying an OCI Web Application Firewall 

Created a blog that walks through the process of configuring a load balancer for a web server hosted on an Oracle Cloud compute instance and securing it with OCI Web Application Firewall (WAF) as part of a comprehensive security strategy. The blog will be published soon after the publishing process is complete. I will link it in this website once this process is over.


# Static Analysis Demo

In this demo, I performed static malware analysis on a keylogger executable and Python script to identify its functionality and potential threats without executing it. By extracting metadata, analyzing embedded strings, and verifying hashes against threat intelligence databases, I uncovered key indicators of compromise (IOCs) and assessed the malware’s behavior. 
Key Steps:

* Keylogger Creation & Analysis: Developed a basic keylogger to understand how malicious keylogging software is structured.

* Executable & Python Script Analysis: Examined PE headers and imports.

* Hash Analysis: Generated MD5, SHA-256 hashes and cross-referenced them with open-source threat intelligence platforms (VirusTotal).

* Embedded String Extraction: Used strings analysis to uncover potential file paths.

* Threat Intelligence Correlation: Checked the MD5 hash in public databases to see if it matched any known malware signatures.


Key Takeaways:

* Identified static indicators of a keylogger.

* Demonstrated low-risk malware analysis techniques that can be applied in real-world security operations.

* Validated findings using open-source intelligence (OSINT) tools to strengthen detection capabilities.

Navigate to the below link for the full walk-through.

[Static Analysis Demo](https://youtu.be/vjDuOHOMlJc?si=TqcFx6O982eB3LV_) 

## Dynamic Analysis Demo

In this demo, I performed dynamic malware analysis on a keylogger executable and Python script, observing its real-time behavior in a sandboxed environment while also testing its ability to bypass Windows Defender and built-in security mechanisms. This included analyzing process execution, file system modifications, network activity, and anti-virus evasion techniques.

Key Steps:

* Safe Execution Environment: Deployed the malware in an isolated virtual machine to prevent host system compromise.

* Windows Defender Evasion: Obfuscated the script/executable to avoid signature-based detection.

* Used custom packing techniques to prevent AV detection.

* Tested execution against Windows Defender and noted bypassed security alerts.

* Keylogging Behavior Analysis: Verified that the malware successfully captured keystrokes and logged them without detection.


Key Takeaways:

* Successfully bypassed Windows Defender using obfuscation and packing techniques.

* Demonstrated how keyloggers operate dynamically, confirming findings from static analysis.

* Identified key persistence mechanisms and stealth techniques used by malware.

* Gained hands-on experience in behavior-based malware detection and defense evasion tactics.


Navigate to the below link for the full walk-through.

[Dynamic Analysis Demo](https://youtu.be/RvHy83w9o5A?si=A4rtUoZElggDOkA1) 


# Coffee Chats | OCI, APEX, SQL

* 	Developed a matching app using Oracle APEX to facilitate weekly virtual dates by randomly pairing users based on preferences and availability.
* 	Created random pairing algorithms with SQL to ensure a dynamic and engaging match experience, ensuring no repeat pairings and leveraging user preferences for better matches.
* 	 Designed and optimized SQL queries for retrieving and updating user profiles, match histories, and pairing statuses, ensuring performance scalability as the app grew.

# Secure Cloud Architectures: OCI IAM and WAF

* 	Designed and implemented a comprehensive cloud security architecture using OCI Cloud Guard, IAM policies, and Web Application Firewalls (WAFs) to protect cloud infrastructure and applications from security threats.
* 	Leveraged OCI Cloud Guard to proactively monitor and detect potential security risks across cloud resources, automating threat identification and remediation actions.
* 	Developed and enforced role-based access controls (RBAC) through OCI IAM policies, ensuring secure, granular access management and aligning permissions with the principle of least privilege.
* 	Configured Web Application Firewalls (WAFs) to safeguard web applications from common threats like SQL injection, cross-site scripting (XSS), and distributed denial-of-service (DDoS) attacks.




