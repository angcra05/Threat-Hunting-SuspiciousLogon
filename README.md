# Threat-Hunting-SuspiciousLogon
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://i.imgur.com/jJtO5hk.png" alt="Tor Logo with the onion and a crosshair on it"/>

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)

##  Scenario
“My machine was throwing login prompts at me through the night. I ignored it and went back to sleep. Seems fine this morning. Can someone take a look?”

Your mission: Investigate. Decide if this was nothing or something real. If it is real, reconstruct what happened, what got touched, and where the attacker ended up. Along the way you will capture 11 flags. Finish with an investigation report and a containment plan.

Starting point: Microsoft Defender portal (security.microsoft.com), Advanced Hunting.

Focus window: 22 April 2026, 04:30 to 06:00 UTC.

Target host: npt-ws01


### High-Level IoC Discovery Plan

- let start_time = datetime(2026-04-22T02:00:00.00Z);

- let end_time = datetime(2026-04-22T08:00:00.00Z);

- let HostInQuestion = "npt-ws01";


---

## Steps Taken

### 1. Flag ONE

Skill: Authentication events; recognising a suspicious logon.

Objective: Mark was getting login prompts all night. Find the account the attacker actually succeeded with and then operated under — hint: it’s not Mark's own account.

Capture: the value shown in DeviceLogonEvents  →  AccountName

Flag: helpdesk


**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where ActionType contains "success"
```
**Image of Results**

<img width="1212" alt="image" src="https://i.imgur.com/UItfVMw.png">

---

### 2. Flag 2 — The Source


Skill: Tying a logon to an external source address.

Objective: Find the external IP address the attacker authenticated from.

Capture: the value shown in DeviceLogonEvents  →  RemoteIP

Flag: 20.110.92.50

**Query used to locate event:**

```kql

let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where AccountName contains "helpdesk"
|where ActionType contains "success"
|where isnotempty( RemoteIP)
|project TimeGenerated, AccountName, RemoteIP, RemoteIPType
```
**Image of Results**

<img width="1212" alt="image" src="https://i.imgur.com/XwSFEL6.png">

---

### 3. Flag 3 — The Process

Skill: Process execution and command-line analysis.

Objective: Find the command line that launched the implant. It carries a recognisable remote-execution signature.

Capture: the value shown in DeviceProcessEvents  →  ProcessCommandLine

Flag: cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe" 1> \Windows\Temp\uYgvso 2>&1

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where AccountName == "helpdesk"
```
**Image of Results**

<img width="1212" alt="image" src="https://i.imgur.com/7erU2id.png">

---

### 4. Flag 4 — The Tree

Skill: Parent-child process relationships; reconstructing the chain.

Objective: Identify the immediate parent process that spawned that cmd.exe. This is what confirms remote WMI execution rather than a local user.

Capture: the value shown in DeviceProcessEvents  →  InitiatingProcessFileName

Flag: wmiprvse.exe 

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where AccountName == "helpdesk"
```
**Image of Results**

<img width="1212" alt="image" src="https://i.imgur.com/LJGoW0I.png">

---


### 5. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceNetworkEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where InitiatingProcessAccountName == "helpdesk"
|project TimeGenerated, DeviceName,RemoteUrl, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://i.imgur.com/dKV3z0a.png">

---

### 6. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceFileEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where FolderPath contains "windowsupdate"
|project TimeGenerated, DeviceName,FileName,FolderPath, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://i.imgur.com/9FVHqxP.png">

---

### 7. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 8. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where ProcessCommandLine contains "/tn"
|project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://i.imgur.com/yCSbWDl.png">

---

### 9. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where ProcessCommandLine contains "/tn"
|project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="">

---

### 10. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
|where TimeGenerated between (start_time ..end_time)
|where DeviceName == HostInQuestion
|where LogonId == "999"
|where ProcessCommandLine contains "net user"
|project TimeGenerated, DeviceName, ProcessCommandLine
```
<img width="1212" alt="image" src="https://i.imgur.com/RwC9lEF.png">

---

### 11. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
AlertEvidence
|where TimeGenerated between (start_time ..end_time)
|where isnotempty(DeviceName)
| join kind=inner (AlertInfo | where Timestamp between (start_time ..end_time)) on AlertId
| summarize AlertCount = count(),
            UniqueAlerts = dcount(AlertId),
            AlertTitles = make_set(Title)
          by DeviceName
| sort by AlertCount desc
```
<img width="1212" alt="image" src="https://i.imgur.com/7fEXqLy.png">
<img width="1212" alt="image" src="https://i.imgur.com/PPe56Kd.png">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
