<div align="center">

# 🧅 Threat Hunt Report: Unauthorized TOR Usage

### Official Internship [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="380" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

[![Platform](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](#platforms-and-languages-leveraged)
[![EDR](https://img.shields.io/badge/EDR-Microsoft%20Defender%20for%20Endpoint-00A4EF?style=flat-square&logo=windowsdefender&logoColor=white)](#platforms-and-languages-leveraged)
[![Query Language](https://img.shields.io/badge/Query%20Language-KQL-4479A1?style=flat-square)](#platforms-and-languages-leveraged)
[![Status](https://img.shields.io/badge/Status-Resolved-success?style=flat-square)](#response-taken)

**📄 Related:** [Scenario Creation](https://github.com/EihabKK/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

</div>

<br>

## 📑 Table of Contents

- [Platforms and Languages Leveraged](#platforms-and-languages-leveraged)
- [Scenario](#-scenario)
- [Steps Taken](#-steps-taken)
- [Timeline of Events](#-timeline-of-events)
- [Summary](#-summary)
- [Response Taken](#-response-taken)

---

## Platforms and Languages Leveraged

| Component | Detail |
|---|---|
| 🖥️ Environment | Windows 11 Virtual Machines (Microsoft Azure) |
| 🛡️ EDR Platform | Microsoft Defender for Endpoint |
| 🔎 Query Language | Kusto Query Language (KQL) |
| 🧅 Application in Scope | Tor Browser |

---

## 🎯 Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### 🗺️ High-Level TOR-Related IoC Discovery Plan

| Step | Table | Objective |
|---|---|---|
| 1 | `DeviceFileEvents` | Check for any `tor(.exe)` or `firefox(.exe)` file events |
| 2 | `DeviceProcessEvents` | Check for any signs of installation or usage |
| 3 | `DeviceNetworkEvents` | Check for any signs of outgoing connections over known TOR ports |

---

## 🔍 Steps Taken

### 1️⃣ Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "ekvm" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop at 2026-07-11T08:18:54.9073293Z.

<details>
<summary><strong>▶ Query used to locate events</strong></summary>

```kql
DeviceFileEvents
|where DeviceName == "ekvm"
| where FileName has_any ("tor")
| order by Timestamp desc    
| project Timestamp, DeviceName, ActionType, FileName, SHA256, InitiatingProcessAccountName
```

</details>

<img width="1752" height="805" alt="image" src="https://github.com/user-attachments/assets/a023ac3a-97cc-4fb9-8e13-3868ae958c40" />

---

### 2️⃣ Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.17.exe /S". Based on the the logs returned, at
2026-07-11T08:12:07.8552813Z, an employee on the "ekvm" device ran the file tor-browser-windows-x86_64-portable-15.0.17.exe /S from their Downloads folder, using a command that triggered a silent installation.

<details>
<summary><strong>▶ Query used to locate event</strong></summary>

```kql
DeviceProcessEvents
| where DeviceName == "ekvm"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.17.exe"
| project Timestamp, DeviceName, ActionType, AccountName, SHA256, ProcessCommandLine
```

</details>

<img width="1763" height="618" alt="image" src="https://github.com/user-attachments/assets/8567e676-be06-41d7-a589-e55cc6ecac3f" />

---

### 3️⃣ Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user "employee" actually opened the tor browser. There was evidence that they did open it at 2026-07-11T08:12:43.7777455Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

<details>
<summary><strong>▶ Query used to locate events</strong></summary>

```kql
DeviceProcessEvents
| where DeviceName == "ekvm"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe","start-tor-browser.exe","torbrowser.exe","tor-browser-windows-x86_64-*.exe","tor-browser-windows-i686-*.exe","tor-browser-windows-x86_64-portable-*.exe","firefox.real.exe","plugin-container.exe")
| project Timestamp, DeviceName, ActionType, AccountName, SHA256,FolderPath, ProcessCommandLine
| order by Timestamp desc
```

</details>

<img width="1737" height="796" alt="image" src="https://github.com/user-attachments/assets/763e26bf-61b1-41f7-b01b-a17cacddaf99" />

---

### 4️⃣ Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-07-11T08:12:54.0719267Z, the device ekvm successfully established a network connection to the remote IP address 141.105.130.172 over port 9001. The connection was initiated by the Tor process (tor.exe), which was running under the ekvm user account from the directory C:\Users\ekvm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. This indicates that the Tor Browser installation on the device was actively communicating with a Tor network relay.

<details>
<summary><strong>▶ Query used to locate events</strong></summary>

```kql
DeviceNetworkEvents
|where DeviceName == "ekvm" 
|where InitiatingProcessAccountName != "system"
| where RemotePort in (80,443,9001,9030,9040,9050,9051,9150)
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
|order by Timestamp desc 
```

</details>

<img width="1783" height="792" alt="image" src="https://github.com/user-attachments/assets/c41a37c1-2bc4-4920-b625-8f9e05e0c5e3" />

---

## 🕒 Timeline of Events

### 1. TOR Installer Download

**Timestamp:** `2026-07-11T04:10:25Z – 2026-07-11T04:10:30Z`

**Event:** The user **"ekvm"** prepared and created a file named **tor-browser-windows-x86_64-portable-15.0.17.exe** on the local system.

**Action:** File rename and file creation detected.

**File Path:** `C:\Users\ekvm\Downloads\tor-browser-windows-x86_64-portable-15.0.17.exe`

---

### 2. Silent TOR Installation

**Timestamp:** `2026-07-11T04:12:07Z`

**Event:** The user **"ekvm"** executed **tor-browser-windows-x86_64-portable-15.0.17.exe** in silent mode, initiating a background installation of the TOR Browser.

**Action:** Process creation detected.

**Command:** `tor-browser-windows-x86_64-portable-15.0.17.exe /S`

**File Path:** `C:\Users\ekvm\Downloads\tor-browser-windows-x86_64-portable-15.0.17.exe`

---

### 3. TOR Browser Execution

**Timestamp:** `2026-07-11T04:12:43Z`

**Event:** User **"ekvm"** launched the **TOR Browser**. Associated processes including **firefox.exe** and **tor.exe** were created, confirming a successful launch.

**Action:** Process creation of TOR Browser-related executables detected.

**File Path:** `C:\Users\EKVM\Desktop\Tor Browser\Browser\tor.exe`

---

### 4. Initial TOR Network Connection

**Timestamp:** `2026-07-11T04:12:50Z`

**Event:** A network connection to **178.239.17.187:9001** was established by **tor.exe**, confirming TOR network activity.

**Action:** Connection success.

**Process:** `tor.exe`

**File Path:** `C:\Users\EKVM\Desktop\Tor Browser\Browser\tor.exe`

---

### 5. Additional TOR Relay Connections

**Timestamps:**
- **2026-07-11T04:12:51Z** – Connected to a remote relay over **port 9001**
- **2026-07-11T04:12:54Z** – Connected to **136.243.92.194:9001**
- **2026-07-11T04:12:54Z** – Connected to **141.105.130.172:9001**
- **2026-07-11T04:13:03Z** – Local connection to **127.0.0.1:9150**

**Event:** Additional TOR relay connections were established, indicating continued TOR Browser activity.

**Action:** Multiple successful connections detected.

---

### 6. TOR Shopping List Creation

**Timestamp:** `2026-07-11T04:18:54Z`

**Event:** The user **"ekvm"** created a file named **tor shopping list.txt** on the desktop.

**Action:** File creation detected.

**File Path:** `C:\Users\EKVM\Desktop\tor shopping list.txt`

---

## 📋 Summary

On July 11, 2026, the user account ekvm bypassed software restrictions by running a portable Tor Browser installer with a silent background parameter (/S), extracting the executable environment directly into a user-writable desktop directory to evade administrative alerts. Upon launch, the application configured a local SOCKS tunnel (127.0.0.1:9150) and established encrypted connections to multiple external Tor relay nodes (178.239.17.187, 136.243.92.194, and 141.105.130.172) over port 9001, completely circumvention network perimeter controls. The employee then engaged in an active, multi-page browsing session spanning over twenty consecutive browser tabs before concluding the activity by generating a custom file directly on the desktop titled tor shopping list.txt. It is recommended to immediately isolate the host, harvest the text artifact for content verification, and enforce application restriction policies to block execution from user-writable directories.

---

## ✅ Response Taken

**TOR usage was confirmed on endpoint EKVM.** The device was isolated and the user's direct manager was notified.

---

<div align="center">

*End of Report*

</div>
