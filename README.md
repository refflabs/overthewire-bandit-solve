# OverTheWire Bandit Automated Solver 🎯

An automated end-to-end Python solver and CTF walkthrough script for the [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) wargame (Levels 0 to 34).

Designed to demonstrate practical Linux command-line exploitation, binary handling, network socket communication, SSL/TLS handshakes, cron timing exploits, restricted shell escapes, and Git credential recovery.

---

## 🛠️ Features & Concepts Covered

- **SSH Automation (`paramiko`)**: Non-interactive command execution, RSA/OpenSSH private key authentication, and pseudo-terminal (PTY) allocation.
- **File System Inspection**: Handling dashed filenames (`./-`), spaces, hidden files, ASCII filtering, and `find` by permissions/byte size.
- **Decompression Chains**: Reversing hexdump (`xxd -r`) and unpacking recursive archives (`gzip`, `bzip2`, `tar`).
- **Network Daemons & Encryption**:
  - Raw socket communication via `netcat`.
  - SSL/TLS handshake automation via `openssl s_client`.
  - Port scanning localhost services.
- **Privilege Escalation & Cronjobs**:
  - Exploiting SUID binaries (`bandit20-do`, `bandit27-do`).
  - Analyzing scheduled cron jobs and directory spooling.
- **Restricted Shell Breakouts**:
  - `more` pagination breakout via terminal window dimension manipulation into `vim` (`:set shell=/bin/bash`).
  - Uppercase shell escape via `$0` positional parameter.
- **Git Version Control Forensics**:
  - Remote repository cloning with `SSH_ASKPASS` automation.
  - Inspecting commit diffs (`git log -p`), remote branches (`git branch -a`), and annotated tags (`git tag`).
  - Solving git pre-receive hook challenge by committing and pushing.

---

## 🚀 Installation & Requirements

### 1. Prerequisites
- Python 3.9+
- Git installed and accessible via PATH
- OpenSSH client

### 2. Install Dependencies
```bash
git clone https://github.com/refflabs/overthewire-bandit-solve.git
cd overthewire-bandit-solve
pip install -r requirements.txt
```

---

## 💻 Usage

Run the solver script directly:

```bash
python bandit_solver.py
```

The script will solve every level in real-time, print progress along with captured passwords, and automatically save all retrieved credentials to `passwords.json`.

---

## 📜 Password Reference (Summary)

| Level Range | Core Challenge |
| :--- | :--- |
| **0 – 6** | Basic navigation, special characters, file attributes, size filtering |
| **7 – 11** | Text processing (`grep`, `sort`, `uniq`, `strings`), Base64, ROT13 |
| **12 – 13** | Hexdump inversion & multi-layer compression extraction |
| **14 – 16** | Local port connections (`nc`, `openssl s_client`, SSL port scan) |
| **17 – 20** | `diff`, `.bashrc` logout bypass, SUID binary, localhost socket matching |
| **21 – 24** | Cron jobs analysis, MD5 hashing, cron spooling, 4-digit PIN brute-force |
| **25 – 27** | PTY `more` / `vim` breakout, secondary SUID escalation |
| **28 – 31** | Git forensics (commit history, branches, tags, remote pushing) |
| **32 – 34** | Uppercase restricted shell breakout (`$0`) & Game completion |

---

## ⚖️ Disclaimer
This project is intended strictly for educational purposes and learning cybersecurity concepts. If you are actively participating in the OverTheWire Bandit wargame, try solving the levels manually first to maximize your learning experience!
