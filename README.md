# C2C CTF 2026 Qualifiers Write-ups & Solvers

**Team:** .schnez  
**Author:** Ibnu Dwiki Hermawan  
**Institution:** Kalimantan Institute of Technology  
**Total Flags Solved:** 12  
**Date:** February 18, 2026 

## 📝 Overview

This repository contains the exploit scripts, payloads, and solution methodologies for the **Country-to-Country (C2C) Capture The Flag 2026 Qualifiers**. The solutions cover various categories including Blockchain, Forensics, Pwn, Reverse Engineering, and Web Exploitation.

For a detailed walkthrough, please refer to the full PDF write-up included in this repo: `C2C2026_WriteUp_Ibnu Dwiki Hermawan_Indonesia.pdf`.

## 📂 Challenge Solutions

### 🔗 Blockchain
| Challenge | Vulnerability / Technique | Script |
| :--- | :--- | :--- |
| **tge** | State Manipulation (Snapshot Logic Flaw) | [solve.py](./Blockchain/tge/solve.py) |
| **Convergence** | Logic Error in Array Sum Validation | [solve.py](./Blockchain/Convergence/solve.py) |
| **nexus** | ERC4626 Inflation/Donation Attack | [exploit.py](./Blockchain/nexus/exploit.py) |

### 🔍 Forensic
| Challenge | Vulnerability / Technique | Script |
| :--- | :--- | :--- |
| **Log** | Blind SQL Injection Log Analysis (Regex) | [log_parser.py](./Forensic/Log/log_parser.py) |
| **Tattletale** | Linux Keylogger (`input_event` struct) & OpenSSL Decryption | [parse_keys.py](./Forensic/Tattletale/parse_keys.py) |

### 🛡️ Pwn
| Challenge | Vulnerability / Technique | Script |
| :--- | :--- | :--- |
| **ns3** | Arbitrary File Write to `/proc/self/mem` & Shellcode Injection | [exploit.py](./Pwn/ns3/exploit.py) |

### ⚙️ Reverse Engineering
| Challenge | Vulnerability / Technique | Script |
| :--- | :--- | :--- |
| **bunaken** | JS Obfuscation (Bun Runtime) & AES-CBC Decryption | [decrypt.py](./Reverse-Engineering/bunaken/decrypt.py) |

### 🌐 Web Exploitation
| Challenge | Vulnerability / Technique | Script |
| :--- | :--- | :--- |
| **Misc: JinJail** | Python/Jinja2 Sandbox Escape via `numpy.f2py` | [payload.txt](./Misc/JinJail/payload.txt) |
| **corp-mail** | Python Format String Injection & JWT Forgery (HS256) | [forge_jwt.py](./Web/corp-mail/forge_jwt.py) |
| **clicker** | JKU Parser Logic Flaw & Curl Globbing Bypass | [gen_jwks.py](./Web/clicker/gen_jwks.py) |
| **Soldier of God** | SSTI (Go Templates) & Integer Truncation (64-bit to 32-bit) | [payload.sh](./Web/The-Soldier-of-God-Rick/payload.sh) |

---

## 🤖 AI Usage Declaration

In compliance with the C2C 2026 rules regarding AI Transparency, the following details adhere to the "New Rules" and "General AI Usage Policy" outlined in the competition guidelines.

* **Did you use AI?** Yes
* **Primary Model:** Gemini 3 Pro
* **Subscription Tier:** Google AI Pro Free for Student (via Google for Education)

**Methodology:**
AI was strictly used as an accelerator, primarily for generating boilerplate code (e.g., `web3.py` connection templates, `pwntools` skeletons) and explaining specific library documentation or obfuscation logic. All exploits were manually verified, debugged, and executed. [cite_start]No flag was submitted blindly from AI output[cite: 20, 21, 22].

---

## 🚀 Setup & Installation

To reproduce the Python scripts, install the required dependencies:

```bash
pip install -r requirements.txt
