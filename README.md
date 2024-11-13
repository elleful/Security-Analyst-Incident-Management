# INCIDENT RESPONSE AND REVIEW - SPRINT 
You've been hired to come in as a security analyst on a team working for Maven Clinic. Maven Clinic, a file transfer platform, recently flagged some unusual network activity that has raised alarms. Your task is to identify the nature of this alert, its potential impact, suggest mitigation strategies, and complete a review. You will be working closely with the CTO to complete this project. 


## Objective

Responsible for handling and mitigating threats based on the NIST Incident Response Process Framework.


### Skills Utilized

- Threat Intelligence
- MITRE ATT&CK TTPs
- Host and Firewall Log Analysis
- Network Analysis
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

![Screenshot of VirusTotal File Hash Analysis](https://i.imgur.com/QrxlMAz.png)


*Ref 1: File Hash Analysis*

***Network Traffic and IP Log Analysis***
Lots of international IP traffic despite being a NY medical clinic.

IPs with positives:
117.80.77.27 (http://117.80.77.27 and https://177.80.77.27) 1 Positive

185.106.39.198 (https://13989180986.com) 1 Positive

***80.172.96.91 Claranet Limited 67 Detections.***
Showing communicating files -1 communicated file and 7 referrer files -  (type Win32 EXE) name bcwvzwbh.exe based out of Portugal 

![VirusTotal Detection - Photo 1](https://i.imgur.com/FzJW6Jw.png)
![VirusTotal Detection - Photo 2](https://i.imgur.com/OpEgfx9.png)
![VirusTotal Detection - Photo 3](https://i.imgur.com/OY1sS2I.png)



## Conclusion

An end-of-project review of key information and reflections overall.

*updating at end of sprint March 2024*.
