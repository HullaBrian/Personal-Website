---
layout: post
title: "A Nightmare on EDR Street: WDAC's Revenge"
subtitle: ""
thumbnail-img: /assets/img/nightmare-on-edr-street/icon.jpg
share-img: /assets/img/nightmare-on-edr-street/icon.jpg
author: Jonathan Beierle
tags: ["Windows Security", "Malware Analysis", "Offensive Tradecraft"]
---

*This is an extension and retrospective of my previous research on creating Windows Defender Application Control (WDAC) policies to disable Endpoint Detection and Response (EDR) agents. The previous post can be found [here](https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/)*

- [Introduction](#introduction)
- [Retrospectives](#retrospectives)
	- [Samples Seen in the Wild and Take-Aways from Dropped Policies](#samples-seen-in-the-wild-and-take-aways-from-dropped-policies)
	- [Cyber Criminal Activity](#cyber-criminal-activity)
	- [Industry Response](#industry-response)
- [Research Updates](#research-updates)
	- [New Malware Family - DreamDemon](#new-malware-family---dreamdemon)
		- [General Attributes](#general-attributes)
		- [Policy Drop](#policy-drop)
		- [Oddities](#oddities)
		- [IOCs and Referenced Paths](#iocs-and-referenced-paths)
	- [Policy Improvements](#policy-improvements)
	- [Technique Developments](#technique-developments)
	- [YARA Tuning](#yara-tuning)

# Introduction
After releasing research detailing the use of Windows Defender Application Control (WDAC) in late December 2024, there have been a number of interesting developments that have resulted in the creation of this post. The research was originally meant to be a proof-of-concept for the technique, but developments since its release have indicated that cybercriminals have taken an interest in the technique. This, coupled with the general lack of preventative capabilities from EDR vendors, is a dangerous combination.

While this blog post will cover retrospectives, it will also cover new developments of the WDAC policy as well as overall offensive WDAC tradecraft which may be used by threat actors. Unlike the last post, there won’t be any tool releases or updates, since updating the PoC would likely cause more harm than good.

# Retrospectives
## Samples Seen in the Wild and Take-Aways from Dropped Policies
Shortly after releasing the original research I set up a YARA rule that actively hunted for new Krueger samples. Below is a table containing a few matches seen since beginning the hunt:

| SHA256 Hash                                                        | Type    | Submission Date           |
| ------------------------------------------------------------------ | ------- | ------------------------- |
| `518da706d95c1edaae73f9fdccb4740b491607542bbbc62d31e2965749b19f91` | Krueger | `2025-02-24 23:15:33 UTC` |
| `90937b3a64cc834088a0628fda9ce5bd2855bedfc76b7a63f698784c41da4677` | Krueger | `2025-01-10 20:11:06 UTC` |
| `a795b79f1d821b8ea7b21c7fb95d140512aaef5a186da49b9c68d8a3ed545a89` | Krueger | `2025-08-14 02:23:34 UTC` |
| `a41a2f5c531212a07ade7b3bed06b21eccfb686cd6cce053a6fab892171a372f` | Krueger | `2025-03-24 14:53:44 UTC` |
| `073e2a7e639a6dd7d406828bf7c8d51ffe67a2c287df88ba72b65d01923f3f43` | Krueger | `2025-06-01 17:43:24 UTC` |

After analyzing the policies embedded within the samples, I gathered the following collection of rules:

| Allow/Block | Rule Type        | Value                                                                   | Targeted Vendor(s) |
| ----------- | ---------------- | ----------------------------------------------------------------------- | ------------------ |
| Block       | File Path        | `%OSDRIVE%\Program Files (x86)\Symantec\Symantec Endpoint Protection\*` | Symantec           |
| Block       | File Path        | `%OSDRIVE%\Program Files (x86)\Tanium\*`                                | Tanium             |
| Block       | File Path        | `%OSDRIVE%\Program Files\CrowdStrike\*`                                 | CrowdStrike        |
| Block       | File Path        | `%SYSTEM32%\drivers\CrowdStrike\*`                                      | CrowdStrike        |
| Block       | File Path        | `%SYSTEM32%\drivers\SEP\*`                                              | Symantec           |
| Block       | File Path        | `%SYSTEM32%\drivers\Tanium*`                                            | Tanium             |
| Allow       | File Path        | `%OSDRIVE%\Users\Public\*`                                              |                    |
| Block       | File Name        | `CSAgent.sys`                                                           | CrowdStrike        |
| Block       | File Description | `Windows Defender Advanced Threat Protection Service Executable`        | Microsoft          |
| Block       | File Description | `Antimalware Service Executable`                                        | Microsoft          |
| Block       | File Description | `Antimalware Core Service`                                              | Microsoft          |
| Block       | File Description | `CrowdStrike Falcon Sensor Driver`                                      | CrowdStrike        |
| Block       | File Description | `CrowdStrike Falcon Sensor`                                             | CrowdStrike        |

Although these rules block the majority of executable code they target, they aren't perfect. For instance, there are 3 file path rules pointing to EDR drivers that likely run in kernel space. However, file path rules cannot block kernel mode code and thus would not entirely block the targeted EDR products. That being said, the policies used by the observed samples could be significantly improved, but I'll get to that later in this post.

Overall, a variety of products have been targeted by WDAC policies including (but not limited to) CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint (MDE), Windows Defender, Velociraptor, Symantec, and Tanium.

## Cyber Criminal Activity
The first that I ever heard of confirmed activity regarding the use of WDAC to kill EDR was from [Beazley Security](https://www.beazley.com), who published details about an [incident they responded to](https://labs.beazley.security/articles/disabling-edr-with-wdac). Unlike the original POC, the threat actors appeared to have leveraged file-signature-based blocks rather than file paths or descriptions. This made the triage process significantly harder due to a lack of recognizable information.

As a secondary item of potential cyber criminal activity, I recently found a new malware family that I've called `DreamDemon` so as to indicate similarity to `Krueger`. I'll dive deeper into the technical details later in this post, but I noticed that the [original file submission](https://www.virustotal.com/gui/file/94bf6cfd0bcaa098769a39dfd6cca50050f26e20f06e8fbdfec103d4b8b303cb/details) for one of the samples was `2025-06-09_d924fbc8593427d9b7cc4bd7bd899718_amadey_black-basta_cobalt-strike_elex_luca-stealer_smoke-loader`, which indicates that this could have come from activity related to Black Basta - a known ransomware gang.

## Industry Response
Overall the industry response has appeared to be positive, with more people taking notice of how even defensive technologies can be leveraged for malicious purposes. That being said, the technique remains just as effective at stopping EDR nearly 9 months after the original blog post was published. While some detection rules have been put out by vendors such as Elastic and CrowdStrike, I have yet to observe any capability (except from MDE) to prevent the abuse of the technique in the first place.

Further, while the initial number of detections from security vendors on VirusTotal for Krueger were relatively low, detections seemed to have jumped to be well over 40/72. Not only that, but many seem to label Krueger samples as either something related to Krueger or WDAC - something I find really cool! (See [VirusTotal Collection](https://www.virustotal.com/gui/collection/f71648f5deb4618be36324c734904cfd59d7325291773f79608b178e0497c931/iocs))

Below is a list of articles/blogs referencing or about the technique and/or Krueger.
- [https://meterpreter.org/krueger-proof-of-concept-poc-net-tool-for-remotely-killing-edr-with-wdac/](https://meterpreter.org/krueger-proof-of-concept-poc-net-tool-for-remotely-killing-edr-with-wdac/)
- [https://cybersecuritynews.com/attack-weaponizes-windows-defender/](https://cybersecuritynews.com/attack-weaponizes-windows-defender/)
- [https://www.pinetworks.net/post/advanced-cyberattack-exploits-windows-defender-to-disable-edr](https://www.pinetworks.net/post/advanced-cyberattack-exploits-windows-defender-to-disable-edr)
- [https://kalilinuxtutorials.com/krueger/](https://kalilinuxtutorials.com/krueger/)
- [https://windowsforum.com/threads/exploiting-wdac-how-attackers-bypass-edr-sensors-and-what-to-do.348590/](https://windowsforum.com/threads/exploiting-wdac-how-attackers-bypass-edr-sensors-and-what-to-do.348590/)
- [https://undercodetesting.com/weaponizing-wdac-killing-the-dreams-of-edr/](https://undercodetesting.com/weaponizing-wdac-killing-the-dreams-of-edr/)
- [https://www.truesec.com/hub/blog/new-wdac-exploit-technique-leveraging-policies-to-disable-edrs-and-evade-detection](https://www.truesec.com/hub/blog/new-wdac-exploit-technique-leveraging-policies-to-disable-edrs-and-evade-detection)
- [https://red.infiltr8.io/redteam/evasion/endpoint-detection-respons-edr-bypass/windows-defender-application-control-wdac-killing-edr](https://red.infiltr8.io/redteam/evasion/endpoint-detection-respons-edr-bypass/windows-defender-application-control-wdac-killing-edr)

# Research Updates
## New Malware Family - DreamDemon
DreamDemon is a malware family that uses WDAC in an attempt to disable defensive tooling such as EDR or AV. It contains an embedded WDAC policy which is then dropped onto disk and hidden. In certain cases, DreamDemon will also change the time that the policy was created in an attempt to avoid detection.

### General Attributes
After analyzing available DreamDemon samples, there were a few key findings that make this family different from Krueger. For one, while Krueger is written in .NET, DreamDemon samples appear to be compiled from C++ code. Further, the samples I have found generally aren't meant to take command line parameters and are instead intended to be run on the target machine directly by impersonating the user that ran it.

![](/assets/img/nightmare-on-edr-street/dreamdemon-run.png)

Similar to Krueger, DreamDemon generally operates in a 4 steps:
1. Load policy from a resource embedded within the executable
2. Place the policy in `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` by referencing a local SMB share (typically `\\localhost\C$`)
3. Hide the policy file and timestomp it
4. Create a log file either in the current working directory as `app.log` or in `C:\Windows\Temp\app_log.log`

### Policy Drop
Before dropping anything to disk, DreamDemon will first load the policy from within itself using `FindResourceW`, `LoadResource`, and `LockResource`

![](/assets/img/nightmare-on-edr-street/code-example-1.png)

Next, it creates the file on the target machine.

![](/assets/img/nightmare-on-edr-street/code-example-2.png)

Finally, it will write the contents of the loaded policy to the file, hide it, and - in some samples - time stomp it.

![](/assets/img/nightmare-on-edr-street/code-example-3.png)

Running DreamDemon samples in a sandbox confirms what the code indicated: a hidden WDAC policy that is timestomped.

![](/assets/img/nightmare-on-edr-street/dreamdemon-file-explorer.png)

### Oddities
Both samples analyzed write some sort of log to disk, either in the current working directory as `app.log` or in `C:\Windows\Temp\app_log.log`

![](/assets/img/nightmare-on-edr-street/dreamdemon-applog-1.png)

![](/assets/img/nightmare-on-edr-street/dreamdemon-applog-2.png)

Unfortunately, I have not analyzed what the data means in the logs, but I suspect it's either garbage output meant to confuse, or some sort of encrypted data. At the very least, the address of the target machine is written to the log. In the first example it is just the address, but in the second it's the full path of the written policy.

Another oddity with one of the samples is that it executes `C:\WINDOWS\system32\cmd.exe /c gpupdate /force > nul 2>&1` after dropping the WDAC policy to disk. What's odd about this is that simply updating group policy after putting a WDAC policy in the code integrity folder doesn't apply the policy. For the group policy update to do anything, the local group policy would already have to be set to point to that specific file path.

### IOCs and Referenced Paths
| SHA256                                                             | Type                   | Submission Date           |
| ------------------------------------------------------------------ | ---------------------- | ------------------------- |
| `94bf6cfd0bcaa098769a39dfd6cca50050f26e20f06e8fbdfec103d4b8b303cb` | DreamDemon Sample      | `2025-06-09 00:41:22 UTC` |
| `2a00212b6f0217a2795aa909be49f91751b3cde1725b54c95450c778072f2308` | DreamDemon Sample      | `2025-07-06 22:22:49 UTC` |
| `31A98D9D66862AD23E8866C4124D8B202DA03FB0B68781FC84F3175ED6D5FBB4` | DreamDemon WDAC Policy | `2025-08-20 04:55:56 UTC` |

Below are the paths referenced by the DreamDemon WDAC policy I obtained. I didn't rigorously test it, but from my basic tests and understanding of WDAC, the paths specifically referencing security products are the block-related rules, while rules such as `%OSDRIVE%\*` are meant to allow normal execution of anything that isn't already denied.
- `%OSDRIVE%\Program Files (x86)\360\*`
- `%OSDRIVE%\Program Files (x86)\Avast Software\Avast\*`
- `%OSDRIVE%\Program Files (x86)\Huorong\*`
- `%OSDRIVE%\Program Files (x86)\kingsoft\kingsoft antivirus\*`
- `%OSDRIVE%\Program Files (x86)\Windows Defender\MpCmdRun.exe`
- `%OSDRIVE%\Program Files\Avast Software\*`
- `%OSDRIVE%\Program Files\kingsoft\kingsoft antivirus\*`
- `%OSDRIVE%\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.exe`
- `%OSDRIVE%\Program Files\Windows Defender\MpCmdRun.exe`
- `%OSDRIVE%\Program Files\Windows Defender\MpCmdRun.exe`
- `%OSDRIVE%\Program Files\Windows Defender\MsMpEng.exe`
- `%OSDRIVE%\Program Files\Windows Defender\NisSrv.exe`
- `%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`
- `%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe`
- `%OSDRIVE%\Users\*\AppData\Roaming\360*\*`
- `%OSDRIVE%\Users\*\AppData\Roaming\360*\*`
- `%SYSTEM32%\SecurityHealthService.exe`
- `%OSDRIVE%\*`
- `D:\*`
- `E:\*`
- `F:\*`
- `G:\*`
- `H:\*`
- `I:\*`
- `J:\*`
- `K:\*`
- `L:\*`
- `M:\*`
- `N:\*`
- `O:\*`
- `P:\*`
- `Q:\*`
- `R:\*`
- `S:\*`
- `T:\*`
- `U:\*`
- `V:\*`
- `W:\*`
- `X:\*`
- `Y:\*`
- `Z:\*`

## Policy Improvements
In the original post detailing this technique the policy used a template policy that only allowed Windows signed executable code as well as a specific path. While this approach worked in blocking EDR, it often caused problems with blocking applications, drivers, or other code that wasn't intended to be blocked. This is what led me to rethink the approach for creating the policy in this technique.

WDAC by default is meant to serve as a "whitelist" approach to application control. That being said, there is a way to turn WDAC policies into a "blacklist." On all versions of Windows 10, 11, and Server 2016+ that I have tested, there exist template application control policies within `C:\Windows\schemas\CodeIntegrity\ExamplePolicies\`. While the majority of these templates provide base rules for certain types of signed executables (i.e. Windows or Microsoft), the `AllowAll.xml` policy is key to improving the efficiency of the malicious WDAC policy, specifically to allow everything in the policy.

In order to create the brand new policy, I copied the `AllowAll.xml` policy and edited it using the WDAC App Control Wizard. I then added rules that blocked the targeted EDR or AV solution and followed the same steps as from the previous post to apply the policy. Once rebooted, the EDR drivers and services were unable to run, and I could execute post-exploitation tooling from where ever I had access to without the constraints of EDR/AV.

## Technique Developments
Improvement was not made on just the policy, however. After releasing the original research, I soon realized that a simple detection for new files being created in the `C:\Windows\System32\CodeIntegrity\` folder would effectively detect the use of the technique. Therefore, I looked into using Group Policy Objects (GPOs) to load WDAC policies from arbitrary locations.

![](/assets/img/nightmare-on-edr-street/Device-Guard-GPO.png)

Contained within group policy, there is a settings that allows system administrators to define a custom location to pull a WDAC policy from. Specifically, in the group policy editor, the path is: `Computer Configuration > Administrative Templates > System > Device Guard > Deploy Windows Defender Application Control`. This settings defines a location - whether it be on the **filesystem or remote SMB share** - that Windows will copy and apply the policy. With this setting there are a few things of note:
- The policy is copied to `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b`, then applied to the system before EDR drivers load
- The original policy doesn't have to be named `SiPolicy.p7b`, it can be named something completely different like `work-project.pdf`
- The policy needs to be in a place that the `SYSTEM` account on the machine has access to

As mentioned at the beginning of this post, I will not be releasing any sort of code to reproduce this technique, but for those looking to detect the potential use of this technique, ensure that you watch the following registry keys:
- `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`
    - `ConfigCIPolicyFilePath` - Will be set to the path of the WDAC policy
    -  `DeployConfigCIPolicy` - Will be set to `1` if enabling WDAC
- `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DeviceGuard`
    - `ConfigCIPolicyFilePath`
    -  `DeployConfigCIPolicy`

Another area of potential detection is that of the file type. WDAC policies have very specific [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures), which when paired with the given file extension may reveal a mismatch. In the example from earlier (`C:\Users\Public\work-project.pdf`), the file still has the magic bytes of a WDAC policy, but the extension indicates that it's a pdf file. This inconsistency may serve in identification.

## YARA Tuning
After analyzing DreamDemon and more Krueger samples, I decided that it would be worth it to both tune the Krueger YARA rule and create a DreamDemon YARA rule. Below are the completed rules. Both the Krueger and DreamDemon rules depend on a rule called `MALDAC` - a YARA rule meant to detect the presence of a WDAC policy that references the paths of known security vendor related files.

```YARA
import "dotnet"

rule MALDAC {
	meta:
		author = "Jonathan Beierle"
		description = "Detects samples designed to use WDAC to disable AV/EDR"
		rule_category = "Technique"
		usage = "Hunting and Identification"
		sample = "94bf6cfd0bcaa098769a39dfd6cca50050f26e20f06e8fbdfec103d4b8b303cb"
		sample = "2a00212b6f0217a2795aa909be49f91751b3cde1725b54c95450c778072f2308"
		sample = "0e5cefbae599c0260f3873a15eaa9b6c2c6125970089d3bc10897bab0b509761"
		sample = "90937b3a64cc834088a0628fda9ce5bd2855bedfc76b7a63f698784c41da4677"
		date_created = "25 August 2025"
        date_updated = ""
		reference = "https://github.com/logangoins/Krueger"
		reference = "https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/"
		reference = "TBD"
	strings:
		/* Strings and bytes used to identify an embedded WDAC policy */
		$wdac_signature = { (07 | 08) 00 00 00 0E }
		$wdac_section_break = { 0E 37 44 A2 C9 44 06 4C B5 51 F6 01 6E 56 30 76 }
		$wdac_deny = { FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 }
		
		/* Potentially targeted security products */
		$product_microsoft_1 = "Windows Defender" wide nocase
		$product_microsoft_2 = "MpCmdRun" wide nocase
		$product_microsoft_3 = "MsMpEng" wide nocase
		$product_microsoft_4 = "NisSrv" wide nocase
		$product_microsoft_5 = "MsSense" wide nocase
		$product_microsoft_6 = "MsDefenderCoreService" wide nocase
		$product_microsoft_7 = "SecurityHealthService" wide nocase
		$product_microsoft_8 = "SenseCncProxy" wide nocase
		$product_microsoft_9 = "Antimalware Service Executable" wide nocase
		$product_microsoft_10 = "Antimalware Core Service" wide nocase
		$product_microsoft_11 = "Windows Defender Advanced Threat Protection Service Executable" wide nocase
		$product_crowdstrike_1 = "CSAgent.sys" wide nocase
		$product_crowdstrike_2 = "CSFalconService.exe" wide nocase
		$product_crowdstrike_3 = "CrowdStrike Falcon Sensor" wide nocase
		$product_crowdstrike_4 = "drivers\\CrowdStrike\\" wide nocase
		$product_crowdstrike_5 = "Program Files\\CrowdStrike\\" wide nocase
		$product_elastic_1 = "Elastic Defend" wide nocase
		$product_elastic_2 = "Elastic-Agent" wide nocase
		$product_tanium_1 = "Tanium" wide nocase
		$product_avast_1 = "Avast" wide nocase
		$product_kingsoft_1 = "kingsoft" wide nocase
		
	condition:
		$wdac_signature
		and #wdac_section_break >= 3
		and #wdac_deny >= 2
		and 2 of ($product_*)
}

rule DreamDemon {
	meta:
		author = "Jonathan Beierle"
		description = ""
		rule_category = "Malware Family"
		sample = "94bf6cfd0bcaa098769a39dfd6cca50050f26e20f06e8fbdfec103d4b8b303cb"
		sample = "2a00212b6f0217a2795aa909be49f91751b3cde1725b54c95450c778072f2308"
		date_created = "25 August 2025"
		date_updated = ""
		reference = "TBD"
	strings:
		/* References to WDAC-related locations
			"\\C$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"\\ADMIN$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"%windir%\\System32\CodeIntegrity\\SiPolicy.p7b"
			"%systemroot%\\System32\CodeIntegrity\\SiPolicy.p7b"
		*/
		$path_ref = "\\System32\\CodeIntegrity\\SiPolicy.p7b" ascii wide
		
		// Parameters for CreateFileA which hide the WDAC policy
		$hide_file_1 = {
			68 02 ?? ?? ??          // push 80000002h ; dwFlagsAndAttributes
			6A 0?                   // push 1         ; dwCreationDisposition
			6A ??                   // push 0         ; lpSecurityAttributes
			6A ??                   // push 0         ; dwShareMode
			68 00 00 00 40          // push 40000000h ; dwDesiredAccess
		}
		
		// Parameters for SetFileAttributesA to hide the WDAC policy
		$hide_file_2 = {
			6A 02                   // push 2                     ; dwFileAttributes 
			8D ?? ??                // lea ecx, [ebp+var_30]
			E8 ?? ?? ?? ??          // call sub_408910
			50                      // push eax                   ; lpFileName
			FF                      // call ds:SetFileAttributesA ; Full instruction omitted for optimization
		}
	condition:
		uint16(0) == 0x5A4D
		and $path_ref
		and MALDAC
		and 1 of ($hide_file_*)
}

rule KRUEGER {
	meta:
		description = "Identifies a Krueger binary"
		author = "Jonathan Beierle"
		reference = "https://github.com/logangoins/Krueger"
		reference = "https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/"
	strings:
		/* References to WDAC-related locations
			"\\C$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"\\ADMIN$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"%windir%\\System32\CodeIntegrity\\SiPolicy.p7b"
			"%systemroot%\\System32\CodeIntegrity\\SiPolicy.p7b"
		*/
		$path_ref = "\\System32\\CodeIntegrity\\SiPolicy.p7b" ascii wide
		
		$Krueger = "Krueger" nocase
		
		$imports_1 = "LogonUser"
		$imports_2 = "Impersonate"
		$imports_3 = "GetManifestResourceStream"
		$imports_4 = "InitiateSystemShutdownEx"
		$imports_5 = "WindowsImpersonationContext"
	
		$wdac_signature = { (07 | 08) 00 00 00 0E }
	condition:
		uint16(0) == 0x5A4D
		and dotnet.is_dotnet
		and dotnet.number_of_resources >= 1
		and for any res in dotnet.resources : (
			$wdac_signature at res.offset  // Check for embedded WDAC policy
		)
		and $path_ref
		and $Krueger
		and MALDAC
		and all of ($imports_*)
}
```