# MIMICRAT ClickFix Campaign Delivering Custom RAT via Compromised Legitimate Websites

- Source: clicksum
- Intake mode: link
- Reference: https://www.elastic.co/security-labs/mimicrat-custom-rat-mimics-c2-frameworks
- Risk level: high
- Confidence: high

## Executive Summary
Elastic Security Labs reported an active February 2026 ClickFix campaign using compromised legitimate websites to socially engineer users into executing an obfuscated PowerShell command. The intrusion chain progresses through a second-stage PowerShell script with ETW and AMSI bypass, a Lua-based shellcode loader, Meterpreter-like shellcode, and a final custom Windows RAT named MIMICRAT. The malware uses HTTPS-based malleable C2, token theft/impersonation, and SOCKS5 tunneling. Compared to the provided detection catalog, there is no material detection overlap with the observed ClickFix delivery chain, staged PowerShell/Lua loader behavior, or MIMICRAT-specific C2 and post-exploitation activity.

## Existing Detection Coverage
- Coverage exists: no
- Coverage summary: The provided catalog is largely APT29- and PsExec-specific and does not materially cover the observed ClickFix social engineering chain, the staged obfuscated PowerShell with AMSI/ETW bypass, Lua-based shellcode loading, or MIMICRAT-specific HTTPS C2, token theft, and SOCKS5 tunneling. While one catalog rule targets generic PowerShell obfuscation, it is narrowly keyed to a different pattern and is not a reliable overlap for this campaign.

_No matching detections were identified._

## Attack Logic
- Victim visits a compromised legitimate website that loads an external malicious script from another compromised site.
- The script presents a fake Cloudflare verification lure and copies a malicious PowerShell command to the victim clipboard.
- User manually executes the clipboard-delivered PowerShell command via Run dialog or PowerShell.
- Stage 1 PowerShell contacts attacker infrastructure to retrieve a second-stage script.
- Stage 2 PowerShell performs ETW and AMSI bypass and drops a Lua-based loader.
- The Lua loader decrypts and executes embedded shellcode fully in memory.
- Shellcode reflectively loads the final MIMICRAT payload.
- MIMICRAT establishes HTTPS C2, supports token theft/impersonation, and enables SOCKS5 tunneling for follow-on operations.

## Impacted Systems
- Windows
- Windows x64 endpoints
- Web browsers
- PowerShell environments

## Likely Targets
- Users visiting compromised legitimate websites
- Enterprise Windows endpoints
- Opportunistic victims across multiple geographies and industries
- Organizations whose users may trust browser-based verification prompts

## TTPs
- ClickFix social engineering via fake verification prompt
- User execution of clipboard-delivered PowerShell
- Obfuscated PowerShell downloader execution
- ETW bypass
- AMSI bypass
- Lua-based in-memory shellcode loader
- Reflective loading of final payload
- HTTPS command and control over port 443
- Malleable HTTP C2 profiles
- Token theft and impersonation
- SOCKS5 tunneling
- Use of compromised legitimate websites for delivery

## Tooling And Malware
- MIMICRAT
- PowerShell
- Custom Lua 5.4.7 loader
- Meterpreter-like shellcode
- ClickFix lure

## Indicators Of Compromise
| Type | Value | Context |
| --- | --- | --- |
| domain | bincheck.io | Compromised legitimate victim-facing entry site used in delivery chain. |
| domain | investonline.in | Compromised legitimate site hosting the malicious ClickFix JavaScript payload. |
| url | https://www.investonline.in/js/jq.php | External malicious script impersonating jQuery and rendering the ClickFix lure. |
| domain | xMRi.neTwOrk | Stage 1 PowerShell download domain reconstructed at runtime. |
| ip | 45.13.212.250 | Resolved IP for xMRi.neTwOrk; infrastructure pivot also linked WexMrI.CC. |
| domain | WexMrI.CC | Additional domain resolving to 45.13.212.250. |
| ip | 45.13.212.251 | Initial payload delivery infrastructure cluster. |
| ip | 23.227.202.114 | Post-exploitation C2 infrastructure cluster. |
| domain | www.ndibstersoft.com | Associated with post-exploitation beacon/C2 communications. |
| domain | d15mawx0xveem1.cloudfront.net | Confirmed CloudFront relay used as part of MIMICRAT C2 infrastructure. |
| uri | /intake/organizations/events?channel=app | Observed GET profile URI pattern tied to MIMICRAT CloudFront C2 relay. |
| file | rgen.zip | Sample referenced in infrastructure analysis contacting the CloudFront domain. |
| file | jq.php | Malicious external script used to present the ClickFix lure. |
| crypto_key | @z1@@9&Yv6GR6vp#SyeG&ZkY0X74%JXLJEv2Ci8&J80AlVRJk&6Cl$Hb)%a8dgqthEa6!jbn70i27d4bLcE33acSoSaSsq6KpRaA7xDypo(5 | RC4 key used to encrypt the MIMICRAT C2 hostname in configuration. |
| string | abcdefghijklmnop | Hardcoded AES IV used in C2 traffic encryption. |

## Recommendations
- Create detections for clipboard-driven or user-executed obfuscated PowerShell launched from browser-to-Run/PowerShell workflows.
- Add analytics for PowerShell patterns consistent with string-slicing reconstruction, runtime ASCII decoding, AMSI bypass, and ETW tampering.
- Hunt for suspicious child-process chains involving browsers, explorer.exe, powershell.exe, and subsequent dropped loader binaries.
- Monitor for Lua-based loaders or uncommon Lua interpreter execution on Windows endpoints.
- Inspect outbound HTTPS traffic for rare domains, CloudFront abuse, and suspicious analytics-like URI patterns used by implants.
- Block or alert on access to listed campaign domains and IPs where operationally appropriate.
- Increase user awareness around fake verification prompts that instruct manual command execution.
- Develop detections for token impersonation abuse and SOCKS5 proxy behavior on Windows hosts.

## References
- https://www.elastic.co/security-labs/mimicrat-custom-rat-mimics-c2-frameworks
