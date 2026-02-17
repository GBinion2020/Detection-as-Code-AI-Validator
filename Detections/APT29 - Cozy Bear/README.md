# APT29 (Cozy Bear / NOBELIUM)

## Notable Attacks

**SolarWinds Supply Chain Compromise (2020), Dark Halo Operations**
- **Targets:** US Government, Fortune 500, SaaS providers
- **Impact:** Long-term espionage via trusted software updates

## Emulation & Detection Strategy

We utilize **Atomic Red Team** to emulate the TTPs associated with the APT29 SolarWinds Supply Chain compromise (2020). While not an exact 1-to-1 replication, this simulation leverages the MITRE ATT&CK framework to model specific adversary behaviors.

Each TTP listed below corresponds to a specific detection rule available in this directory. These detections are managed and deployed using Detection-as-Code (DaC) practices via GitHub Actions.

## ATT&CK Techniques Used

| Phase | Technique | Detection Rule |
| :--- | :--- | :--- |
| Initial Access | T1195 – Supply Chain Compromise | - |
| Initial Access | T1566.002 – Phishing Links | - |
| Execution | T1059.001 – PowerShell | [APT29 PowerShell AutoIt Execution](Execution%20-%20T1059.001.yml) |
| Defense Evasion | T1027 – Obfuscated Files or Information | [APT29 PowerShell Obfuscation](Defense%20Evasion%20-%20T1027.7.yml) |
| Credential Access | T1555.002 - Security Account Manager | [APT29 Credential Exfiltration via GitHub](Credential%20Access%20-%20T1555.002.yml) |
| Discovery | T1082 – System Information Discovery | [APT29 Discovery via WinPwn](Discovery%20-%20T1082.001.yml) |
| Lateral Movement | T1570 – Lateral Tool Transfer | [APT29 Lateral Movement SMB SkipCert](Lateral%20Movement%20-%20T1570.001.yml) |
| Persistence | T1098 – Account Manipulation | [APT29 Persistence Account Manipulation](Persistence%20-%20T1098.001.yml) |
| Command and Control | T1071.001 – Web Protocols | [APT29 C2 Telnet Usage](Command%20and%20Control%20-%20T1071.001.yml) |
| Exfiltration | T1041 – Exfiltration over C2 channel | [APT29 Exfiltration via Invoke-WebRequest](Exfiltration%20-%20T1041.001.yml) |
