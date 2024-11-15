# INCIDENT RESPONSE AND REVIEW - SPRINT 
You've been hired to come in as a security analyst on a team working for Maven Clinic. Maven Clinic, a file transfer platform, recently flagged some unusual network activity that has raised alarms. Your task is to identify the nature of this alert, its potential impact, suggest mitigation strategies, and complete a review. You will be working closely with the CTO to complete this project. 


## Objective

Responsible for handling and mitigating threats based on the NIST Incident Response Process Framework.


### Skills Utilized

- Threat Intelligence
- MITRE ATT&CK TTPs
- Host and Firewall Log Analysis
- Network Analysis
- Data Correlation
- Containment Planning
- Incident Reporting
- Python Scripting
  

### Tools Used

- NIST 800-53 (Security and Privacy Controls for Information Systems)
- NIST 800-61 (Computer Incident Handling Guide)
- Virustotal
- Python
- Log Data


## Analysis Overview

***Red Flags:***
192.168.1.100 - no SID with failed login attempts and then immediate high CPU usage indicated by low memory alert with traffic appearing to be sent to gateway IP 192.168.1.1

192.168.1.25- SSH connection with high CPU usage indicated by low memory alert with traffic appearing to be sent to gateway IP 192.168.1.1

10.0.0.2 internal IP sending data out to the internet through traffic appearing to be sent to gateway IP 10.0.0.1 from an unknown application


**Possible compromised Hosts:**

Desktop-1234567
DC-Server-01

**Possible compromised IPs:**

192.168.1.25
192.168.1.50
192.168.1.100
10.0.0.2


**Needs more research:**

File Open/Close or Read/Write of MS SQL Server warning (log2) might be connected to Application log Error (log1) but the time difference is large.

MS SQL Server warning information was not definitive and could be researched further. Threat Analysis


***Network Traffic and IP Log Analysis***

Lots of international IP traffic despite being a NY medical clinic.

IPs with positives:
117.80.77.27 (HTTP: //117.80.77.27 and https: //177.80.77.27) 1 Positive

185.106.39.198 (https: //13989180986.com) 1 Positive

***80.172.96.91 Claranet Limited 67 Detections.***
Showing communicating files -1 communicated file and 7 referrer files -  (type Win32 EXE) name bcwvzwbh.exe based out of Portugal 

![VirusTotal Detection - Photo 1](https://i.imgur.com/FzJW6Jw.png)
*Ref 1: CC Communication*

![VirusTotal Detection - Photo 2](https://i.imgur.com/OpEgfx9.png)
*Ref 2: IP Identified on network associated with file communication*

![VirusTotal Detection - Photo 3](https://i.imgur.com/OY1sS2I.png)
*Ref 1: 67 Detections*

**Key Behaviors of the malicious file:**
*Note: Appears to have been detected as Linux Trojan Rbot by Elastic Security*

1. Checks for Virtualization/Sandboxes to avoid being debugged (picked apart for data exfiltration of the attacker).
2. File data is also obfuscated and encrypted.
3. Creates an input object to capture keystrokes (records typing on the host to steal credentials).
4. Reads software policies.
5. Enumerates the file system.
6. Opens and writes files.
7. Enumerates registry and sets keys.
8. Creates processes and runs shell commands.


## Conclusion

An employee clicked on a deceptive email link and threat actor gains unauthorized access to the network. There are multiple failed attempts to gain high-level access and altered system settings to reduce detection. Finally, sensitive patient data accessed and virus deployed to exfiltrate information causing network slowdown.  

