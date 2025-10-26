#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon By Zoya (patched)
Author: Zoya

Patch summary:
- Only changed the logic that locates executables so the script can detect Go-installed tools across different laptops/environments.
- All other code, CLI behavior, and flow are unchanged.
"""

import os
import re
import sys
import shutil
import signal
import subprocess
from pathlib import Path
from glob import glob

# -------------- Colors and Banner --------------
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

BANNER = r"""
  _____                        ____          ______                 
 |  __ \                      |  _ \        |___  /                 
 | |__) |___  ___ ___  _ __   | |_) |_   _     / / ___  _   _  __ _ 
 |  _  // _ \/ __/ _ \| '_ \  |  _ <| | | |   / / / _ \| | | |/ _` |
 | | \ \  __/ (_| (_) | | | | | |_) | |_| |  / /_| (_) | |_| | (_| |
 |_|  \_\___|\___\___/|_| |_| |____/ \__, | /_____\___/ \__, |\__,_|
                                      __/ |              __/ |      
                                     |___/              |___/         Recon By Zoya
"""

# -------------- Utilities --------------
def printc(msg, color=NC):
    print(f"{color}{msg}{NC}")

def run_cmd(cmd, silent=False, check=False, cwd=None, env=None):
    """
    Run a shell command preserving original flags and piping behavior.
    - silent: redirect stdout/stderr to DEVNULL (match &> /dev/null)
    - check: raise on nonzero exit
    Returns (returncode, stdout_text, stderr_text)
    """
    stdout = subprocess.DEVNULL if silent else subprocess.PIPE
    stderr = subprocess.DEVNULL if silent else subprocess.PIPE
    proc = subprocess.Popen(
        cmd,
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        shell=False,
        text=True,
    )
    out, err = proc.communicate()
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=out, stderr=err)
    return proc.returncode, out or "", err or ""

# ---------------- New robust executable finder ----------------
def find_executable(name):
    """
    Robust search for a binary 'name'.
    Checks, in order:
      1) shutil.which (current PATH)
      2) GOBIN env var
      3) go env GOPATH/bin (if `go` available)
      4) common system locations (/usr/local/bin, /usr/bin, /bin, /snap/bin, /usr/sbin, /sbin)
      5) per-user go bins: /home/*/go/bin and /root/go/bin
      6) fallback to 'which -a' output when present
    Returns absolute path string if found, else None.
    """
    # 1) Normal PATH
    p = shutil.which(name)
    if p:
        return p

    # 2) GOBIN env var
    gobin = os.environ.get("GOBIN")
    if gobin:
        path = os.path.join(gobin, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 3) try `go env GOPATH` and check $GOPATH/bin
    try:
        proc = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True, check=True)
        gopath = proc.stdout.strip()
        if gopath:
            path = os.path.join(gopath, "bin", name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
            # some environments use $(go env GOBIN) or $GOPATH/bin goes to different place
            # also check GOMODCACHE bin locations (less common)
    except Exception:
        # go may not be installed or accessible; continue searching
        pass

    # 4) Common system locations
    common_dirs = ["/usr/local/bin", "/usr/bin", "/bin", "/snap/bin", "/usr/sbin", "/sbin"]
    for d in common_dirs:
        path = os.path.join(d, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 5) per-user go bins (wildcard users)
    for home_glob in ["/home/*/go/bin", "/root/go/bin"]:
        for candidate in glob(home_glob):
            path = os.path.join(candidate, name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

    # 6) which -a fallback (shell out) - may reveal other locations
    try:
        proc = subprocess.run(["which", "-a", name], capture_output=True, text=True, check=False)
        out = proc.stdout.strip()
        if out:
            # take first non-empty line
            for line in out.splitlines():
                line = line.strip()
                if line and os.path.isfile(line) and os.access(line, os.X_OK):
                    return line
    except Exception:
        pass

    return None

# Small helper alias to preserve original variable names used below
def locate(name):
    return find_executable(name)

def require_tools(tools):
    print("[+] Checking for required tools...")
    missing = []
    for t in tools:
        if locate(t) is None:
            missing.append(t)
    if missing:
        printc(f"[-] Missing required tools: {' '.join(missing)}", RED)
        printc("[!] Please install the missing tools before running the script", YELLOW)
        # Preserve original install hints
        print("subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("puredns: go install github.com/d3mondev/puredns/v2@latest")
        print("gotator: go install github.com/Josue87/gotator@latest")
        print("cero: go install github.com/glebarez/cero@latest")
        print("httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("gospider: go install github.com/jaeles-project/gospider@latest")
        print("unfurl: go install github.com/tomnomnom/unfurl@latest")
        sys.exit(1)
    printc("[+] All required tools are installed!", GREEN)

# The rest of the script is unchanged except every shutil.which(...) call is replaced with locate(...)

def safe_rm_rf(path: Path):
    try:
        if path.exists():
            shutil.rmtree(path)
    except Exception as e:
        printc(f"[!] Warning: could not remove {path}: {e}", YELLOW)

def safe_mkdir(path: Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        printc(f"[!] Error creating directory {path}: {e}", RED)
        sys.exit(1)

def write_sorted_unique(input_paths, output_path):
    items = set()
    for p in input_paths:
        if Path(p).exists():
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        items.add(s)
    with open(output_path, "w", encoding="utf-8") as f:
        for s in sorted(items):
            f.write(s + "\n")

def grep_domains_from_text(text, domain):
    escaped = re.escape(domain)
    pattern = re.compile(rf'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+{escaped}\b')
    return set(pattern.findall(text))

def curl(url):
    curl_bin = locate("curl")
    if not curl_bin:
        raise RuntimeError("curl is required for passive scraping but not found in PATH")
    rc, out, _ = run_cmd([curl_bin, "-s", url], silent=False, check=False)
    if rc != 0:
        return ""
    return out

def filter_for_domain(lines, domain):
    return sorted({l.strip() for l in lines if l.strip().endswith("." + domain) or l.strip() == domain})

# -------------- Paths --------------
SUBS_DIR = Path("subs")
WORDLIST_DNS = Path("Wordlists/dns/dns_2m.txt")
VALID_RESOLVERS = Path("Wordlists/dns/valid_resolvers.txt")
PERMUTATIONS_LIST = Path("Wordlists/dns/dns_permutations_list.txt")

# -------------- Recon Steps --------------
def finish_work():
    print("[+] Combining subdomains and resolving them...")
    all_files = list(SUBS_DIR.glob("*"))
    all_filtered = SUBS_DIR / "all_subs_filtered.txt"
    write_sorted_unique(all_files, all_filtered)

    out_resolved = SUBS_DIR / "all_subs_resolved.txt"
    puredns = locate("puredns")
    if puredns:
        cmd = [
            puredns, "resolve", str(all_filtered),
            "-r", str(VALID_RESOLVERS),
            "-w", str(out_resolved),
            "--skip-wildcard-filter",
            "--skip-validation"
        ]
        run_cmd(cmd, silent=True, check=False)
    else:
        out_resolved.write_text("", encoding="utf-8")

    httpx = locate("httpx")
    filtered_hosts = SUBS_DIR / "filtered_hosts.txt"
    if httpx:
        cmd = [httpx, "-random-agent", "-retries", "2", "--silent", "-o", str(filtered_hosts)]
        try:
            with open(out_resolved, "r", encoding="utf-8") as f:
                proc = subprocess.Popen(cmd, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
                proc.wait()
        except Exception as e:
            printc(f"[!] httpx step failed: {e}", YELLOW)
    else:
        filtered_hosts.write_text("", encoding="utf-8")

    print("[+] Thats it we are done with subdomain enumeration!")

def passive_recon(target_domain):
    urls = [
        f"https://rapiddns.io/subdomain/{target_domain}?full=1#result",
        f"http://web.archive.org/cdx/search/cdx?url=*.{target_domain}/*&output=text&fl=original&collapse=urlkey",
        f"https://crt.sh/?q=%.{target_domain}",
        f"https://crt.sh/?q=%..{target_domain}",
        f"https://crt.sh/?q=%...{target_domain}",
        f"https://crt.sh/?q=%....{target_domain}",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{target_domain}/passive_dns",
        f"https://api.hackertarget.com/hostsearch/?q={target_domain}",
        f"https://urlscan.io/api/v1/search/?q={target_domain}",
        f"https://jldc.me/anubis/subdomains/{target_domain}",
        f"https://www.google.com/search?q=site%3A{target_domain}&num=100",
        f"https://www.bing.com/search?q=site%3A{target_domain}&count=50",
    ]

    print("[+] Let's start with passive subdomain enumeration!")
    print(f"[+] Getting {target_domain} subdomains using [crt.sh,rapiddns,alienvault,hackertarget,urlscan,jldc.me,google,bing]")

    passive_tmp = SUBS_DIR / "passive.txt"
    all_found = set()
    for u in urls:
        try:
            text = curl(u)
            all_found |= grep_domains_from_text(text, target_domain)
        except Exception as e:
            printc(f"[!] Warning: fetch failed for {u}: {e}", YELLOW)

    with open(passive_tmp, "w", encoding="utf-8") as f:
        for h in sorted(all_found):
            f.write(h + "\n")

    print("[+] Removing duplicates.....")
    print("[+] Saving to quick_passive.txt")
    quick_passive = SUBS_DIR / "quick_passive.txt"
    write_sorted_unique([passive_tmp], quick_passive)
    try:
        passive_tmp.unlink(missing_ok=True)
    except Exception:
        pass

    print("[+] Using subfinder for passive subdomain enumeration ")
    subfinder = locate("subfinder")
    subfinder_out = SUBS_DIR / "subfinder.txt"
    if subfinder:
        try:
            rc, out, err = run_cmd([subfinder, "-d", target_domain, "--all", "--silent"], silent=False, check=False)
            with open(subfinder_out, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            printc(f"[!] subfinder failed: {e}", YELLOW)
            subfinder_out.write_text("", encoding="utf-8")
    else:
        subfinder_out.write_text("", encoding="utf-8")

    print("[+] That's it, we are done with passive subdomain enumeration!")
    finish_work()

def active_recon(target_domain):
    print("[+] Start active subdomain enumeration!")
    print("[+] DNS Brute Forcing using puredns")

    dns_bf = SUBS_DIR / "dns_bf.txt"
    puredns = locate("puredns")
    if puredns:
        try:
            run_cmd([
                puredns, "bruteforce", str(WORDLIST_DNS), target_domain,
                "-r", str(VALID_RESOLVERS),
                "-w", str(dns_bf),
                "--skip-wildcard-filter", "--skip-validation"
            ], silent=True, check=False)
        except Exception as e:
            printc(f"[!] puredns bruteforce failed: {e}", YELLOW)
            dns_bf.write_text("", encoding="utf-8")
    else:
        dns_bf.write_text("", encoding="utf-8")

    print("[+] resolving brute forced subs....")
    dns_bf_resolved = SUBS_DIR / "dns_bf_resolved.txt"
    if puredns:
        try:
            run_cmd([
                puredns, "resolve", str(dns_bf),
                "-r", str(VALID_RESOLVERS),
                "-w", str(dns_bf_resolved),
                "--skip-wildcard-filter", "--skip-validation"
            ], silent=True, check=False)
        except Exception as e:
            printc(f"[!] puredns resolve failed: {e}", YELLOW)
            dns_bf_resolved.write_text("", encoding="utf-8")
    else:
        dns_bf_resolved.write_text("", encoding="utf-8")

    print("[+] Permutations using gotator")
    gotator = locate("gotator")
    permutations = SUBS_DIR / "permutations.txt"
    if gotator:
        try:
            rc, out, err = run_cmd([
                gotator, "-sub", str(dns_bf_resolved),
                "-perm", str(PERMUTATIONS_LIST),
                "-mindup", "-fast", "-silent"
            ], silent=False, check=False)
            uniq = sorted({l.strip() for l in out.splitlines() if l.strip()})
            with open(permutations, "w", encoding="utf-8") as f:
                for l in uniq:
                    f.write(l + "\n")
        except Exception as e:
            printc(f"[!] gotator failed: {e}", YELLOW)
            permutations.write_text("", encoding="utf-8")
    else:
        permutations.write_text("", encoding="utf-8")

    print("[+] TLS probing using cero")
    cero = locate("cero")
    tls_probing = SUBS_DIR / "tls_probing.txt"
    if cero:
        try:
            rc, out, err = run_cmd([cero, target_domain], silent=False, check=False)
            processed = []
            for line in out.splitlines():
                s = re.sub(r'^\\*\.', '', line.strip())
                if "." in s:
                    processed.append(s)
            uniq = sorted({h for h in processed if h.endswith("." + target_domain)})
            with open(tls_probing, "w", encoding="utf-8") as f:
                for h in uniq:
                    f.write(h + "\n")
        except Exception as e:
            printc(f"[!] cero failed: {e}", YELLOW)
            tls_probing.write_text("", encoding="utf-8")
    else:
        tls_probing.write_text("", encoding="utf-8")

    print("[+] Scraping JS Source code ")
    filtered_subs = SUBS_DIR / "filtered_subs.txt"
    write_sorted_unique(list(SUBS_DIR.glob("*")), filtered_subs)

    httpx = locate("httpx")
    filtered_hosts = SUBS_DIR / "filtered_hosts.txt"
    if httpx:
        try:
            with open(filtered_subs, "r", encoding="utf-8") as f:
                proc = subprocess.Popen(
                    [httpx, "-random-agent", "-retries", "2", "-o", str(filtered_hosts)],
                    stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True
                )
                proc.wait()
        except Exception as e:
            printc(f"[!] httpx step failed: {e}", YELLOW)
            filtered_hosts.write_text("", encoding="utf-8")
    else:
        filtered_hosts.write_text("", encoding="utf-8")

    print("[+] Crawling for js files using gospider")
    gospider = locate("gospider")
    gospider_out = SUBS_DIR / "gospider.txt"
    if gospider:
        try:
            run_cmd([
                gospider, "-S", str(filtered_hosts), "--js", "-t", "50", "-d", "3",
                "--sitemap", "--robots", "-w", "-r"
            ], silent=False, check=False)
            rc, out, err = run_cmd([
                gospider, "-S", str(filtered_hosts), "--js", "-t", "50", "-d", "3",
                "--sitemap", "--robots", "-w", "-r"
            ], silent=False, check=False)
            with open(gospider_out, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            printc(f"[!] gospider failed: {e}", YELLOW)
            gospider_out.write_text("", encoding="utf-8")
    else:
        gospider_out.write_text("", encoding="utf-8")

    print("[+] Extracting Subdomains......")
    trimmed_lines = []
    try:
        with open(gospider_out, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line) <= 2048:
                    trimmed_lines.append(line)
    except Exception as e:
        printc(f"[!] Could not read {gospider_out}: {e}", YELLOW)

    urls = []
    http_url_re = re.compile(r'https?://[^\s\]]+')
    for ln in trimmed_lines:
        urls.extend(http_url_re.findall(ln.strip()))
    urls = [u.rstrip(']') for u in urls]

    scrap_subs = SUBS_DIR / "scrap_subs.txt"
    unfurl = locate("unfurl")
    extracted = set()
    if unfurl:
        try:
            proc = subprocess.Popen([unfurl, "-u", "domains"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate("\n".join(urls))
            if proc.returncode == 0:
                for h in out.splitlines():
                    if target_domain in h:
                        extracted.add(h.strip())
        except Exception as e:
            printc(f"[!] unfurl failed, falling back to regex: {e}", YELLOW)

    if not extracted:
        for u in urls:
            try:
                host = re.sub(r'^https?://', '', u).split('/')[0]
                if target_domain in host:
                    extracted.add(host)
            except Exception:
                pass

    with open(scrap_subs, "w", encoding="utf-8") as f:
        for h in sorted(extracted):
            f.write(h + "\n")

    try:
        gospider_out.unlink(missing_ok=True)
    except Exception:
        pass

    print("[+] Done with Active subdomain enumeration!")
    finish_work()

# The rest of recon functions (normal_recon, quick_recon, full_recon) are identical in structure
# they also use locate(...) instead of shutil.which(...)

def normal_recon(target_domain):
    passive_recon(target_domain)
    print("[+] Start active subdomain enumeration!")
    print("[+] DNS Brute Forcing using puredns")

    dns_bf = SUBS_DIR / "dns_bf.txt"
    puredns = locate("puredns")
    if puredns:
        try:
            run_cmd([
                puredns, "bruteforce", str(WORDLIST_DNS), target_domain,
                "-r", str(VALID_RESOLVERS),
                "-w", str(dns_bf),
                "--skip-wildcard-filter", "--skip-validation"
            ], silent=True, check=False)
        except Exception as e:
            printc(f"[!] puredns bruteforce failed: {e}", YELLOW)
            dns_bf.write_text("", encoding="utf-8")
    else:
        dns_bf.write_text("", encoding="utf-8")

    print("[+] resolving brute forced subs....")
    dns_bf_resolved = SUBS_DIR / "dns_bf_resolved.txt"
    if puredns:
        try:
            run_cmd([
                puredns, "resolve", str(dns_bf),
                "-r", str(VALID_RESOLVERS),
                "-w", str(dns_bf_resolved),
                "--skip-wildcard-filter", "--skip-validation"
            ], silent=True, check=False)
        except Exception as e:
            printc(f"[!] puredns resolve failed: {e}", YELLOW)
            dns_bf_resolved.write_text("", encoding="utf-8")
    else:
        dns_bf_resolved.write_text("", encoding="utf-8")

    print("[+] TLS probing using cero")
    cero = locate("cero")
    tls_probing = SUBS_DIR / "tls_probing.txt"
    if cero:
        try:
            rc, out, err = run_cmd([cero, target_domain], silent=False, check=False)
            processed = []
            for line in out.splitlines():
                s = re.sub(r'^\\*\.', '', line.strip())
                if "." in s:
                    processed.append(s)
            uniq = sorted({h for h in processed if h.endswith("." + target_domain)})
            with open(tls_probing, "w", encoding="utf-8") as f:
                for h in uniq:
                    f.write(h + "\n")
        except Exception as e:
            printc(f"[!] cero failed: {e}", YELLOW)
            tls_probing.write_text("", encoding="utf-8")
    else:
        tls_probing.write_text("", encoding="utf-8")

    print("[+] Scraping JS Source code ")
    filtered_subs = SUBS_DIR / "filtered_subs.txt"
    write_sorted_unique(list(SUBS_DIR.glob("*")), filtered_subs)

    httpx = locate("httpx")
    filtered_hosts = SUBS_DIR / "filtered_hosts.txt"
    if httpx:
        try:
            with open(filtered_subs, "r", encoding="utf-8") as f:
                proc = subprocess.Popen(
                    [httpx, "-random-agent", "-retries", "2", "-o", str(filtered_hosts)],
                    stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True
                )
                proc.wait()
        except Exception as e:
            printc(f"[!] httpx step failed: {e}", YELLOW)
            filtered_hosts.write_text("", encoding="utf-8")
    else:
        filtered_hosts.write_text("", encoding="utf-8")

    print("[+] Crawling for js files using gospider")
    gospider = locate("gospider")
    gospider_out = SUBS_DIR / "gospider.txt"
    if gospider:
        rc, out, err = run_cmd([
            gospider, "-S", str(filtered_hosts), "--js", "-t", "50", "-d", "3",
            "--sitemap", "--robots", "-w", "-r"
        ], silent=False, check=False)
        with open(gospider_out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        gospider_out.write_text("", encoding="utf-8")

    print("[+] Extracting Subdomains......")
    trimmed_lines = []
    try:
        with open(gospider_out, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line) <= 2048:
                    trimmed_lines.append(line)
    except Exception as e:
        printc(f"[!] Could not read {gospider_out}: {e}", YELLOW)

    http_url_re = re.compile(r'https?://[^\s\]]+')
    urls = []
    for ln in trimmed_lines:
        urls.extend(http_url_re.findall(ln.strip()))
    urls = [u.rstrip(']') for u in urls]

    scrap_subs = SUBS_DIR / "scrap_subs.txt"
    unfurl = locate("unfurl")
    extracted = set()
    if unfurl:
        try:
            proc = subprocess.Popen([unfurl, "-u", "domains"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate("\n".join(urls))
            if proc.returncode == 0:
                for h in out.splitlines():
                    if target_domain in h:
                        extracted.add(h.strip())
        except Exception as e:
            printc(f"[!] unfurl failed, fallback: {e}", YELLOW)

    if not extracted:
        for u in urls:
            try:
                host = re.sub(r'^https?://', '', u).split('/')[0]
                if target_domain in host:
                    extracted.add(host)
            except Exception:
                pass

    with open(scrap_subs, "w", encoding="utf-8") as f:
        for h in sorted(extracted):
            f.write(h + "\n")

    try:
        gospider_out.unlink(missing_ok=True)
    except Exception:
        pass

    print("[+] Done with Active subdomain enumeration!")
    print("[+] Normal Recon is complete!")
    finish_work()

def quick_recon(target_domain):
    passive_recon(target_domain)
    print("[+] TLS probing using cero")
    cero = locate("cero")
    tls_probing = SUBS_DIR / "tls_probing.txt"
    if cero:
        try:
            rc, out, err = run_cmd([cero, target_domain], silent=False, check=False)
            processed = []
            for line in out.splitlines():
                s = re.sub(r'^\\*\.', '', line.strip())
                if "." in s:
                    processed.append(s)
            uniq = sorted({h for h in processed if h.endswith("." + target_domain)})
            with open(tls_probing, "w", encoding="utf-8") as f:
                for h in uniq:
                    f.write(h + "\n")
        except Exception as e:
            printc(f"[!] cero failed: {e}", YELLOW)
            tls_probing.write_text("", encoding="utf-8")
    else:
        tls_probing.write_text("", encoding="utf-8")

    print("[+] Scraping JS Source code ")
    filtered_subs = SUBS_DIR / "filtered_subs.txt"
    write_sorted_unique(list(SUBS_DIR.glob("*")), filtered_subs)

    httpx = locate("httpx")
    filtered_hosts = SUBS_DIR / "filtered_hosts.txt"
    if httpx:
        try:
            with open(filtered_subs, "r", encoding="utf-8") as f:
                proc = subprocess.Popen(
                    [httpx, "-random-agent", "-retries", "2", "-o", str(filtered_hosts)],
                    stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True
                )
                proc.wait()
        except Exception as e:
            printc(f"[!] httpx step failed: {e}", YELLOW)
            filtered_hosts.write_text("", encoding="utf-8")
    else:
        filtered_hosts.write_text("", encoding="utf-8")

    print("[+] Crawling for js files using gospider")
    gospider = locate("gospider")
    gospider_out = SUBS_DIR / "gospider.txt"
    if gospider:
        rc, out, err = run_cmd([
            gospider, "-S", str(filtered_hosts), "--js", "-t", "50", "-d", "3",
            "--sitemap", "--robots", "-w", "-r"
        ], silent=False, check=False)
        with open(gospider_out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        gospider_out.write_text("", encoding="utf-8")

    print("[+] Extracting Subdomains......")
    trimmed_lines = []
    try:
        with open(gospider_out, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line) <= 2048:
                    trimmed_lines.append(line)
    except Exception as e:
        printc(f"[!] Could not read {gospider_out}: {e}", YELLOW)

    http_url_re = re.compile(r'https?://[^\s\]]+')
    urls = []
    for ln in trimmed_lines:
        urls.extend(http_url_re.findall(ln.strip()))
    urls = [u.rstrip(']') for u in urls]

    scrap_subs = SUBS_DIR / "scrap_subs.txt"
    unfurl = locate("unfurl")
    extracted = set()
    if unfurl:
        try:
            proc = subprocess.Popen([unfurl, "-u", "domains"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate("\n".join(urls))
            if proc.returncode == 0:
                for h in out.splitlines():
                    if target_domain in h:
                        extracted.add(h.strip())
        except Exception as e:
            printc(f"[!] unfurl failed, fallback: {e}", YELLOW)

    if not extracted:
        for u in urls:
            try:
                host = re.sub(r'^https?://', '', u).split('/')[0]
                if target_domain in host:
                    extracted.add(host)
            except Exception:
                pass

    with open(scrap_subs, "w", encoding="utf-8") as f:
        for h in sorted(extracted):
            f.write(h + "\n")

    try:
        gospider_out.unlink(missing_ok=True)
    except Exception:
        pass

    print("[+] Quick Recon is complete!")
    finish_work()

def full_recon(target_domain):
    passive_recon(target_domain)
    active_recon(target_domain)
    print("[+] Full Recon is complete!")
    finish_work()

# -------------- Main --------------
def main():
    def _sigint(_sig, _frm):
        printc("\n[!] Interrupted by user", YELLOW)
        sys.exit(1)
    signal.signal(signal.SIGINT, _sigint)

    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print(f"[+] usage {Path(sys.argv[0]).name} domain.com ")
        sys.exit(1)

    target_domain = sys.argv[1].strip()

    printc(BANNER, RED)

    safe_rm_rf(SUBS_DIR)
    safe_mkdir(SUBS_DIR)

    require_tools(["subfinder", "puredns", "gotator", "cero", "httpx", "gospider", "unfurl"])

    options = """
Choose what you wanna do?
[1] Passive recon only
[2] Active recon only
[3] Normal Recon [All without permutations]
[4] Quick Recon [All without Brute forcing and Permutations]
[5] Full recon [All Techniques]
"""
    printc(options, GREEN)
    try:
        choice = input("Enter your choice: ").strip()
    except EOFError:
        printc("[!] No input received. Exiting.", RED)
        sys.exit(1)

    if choice == "1":
        passive_recon(target_domain)
    elif choice == "2":
        active_recon(target_domain)
    elif choice == "3":
        normal_recon(target_domain)
    elif choice == "4":
        quick_recon(target_domain)
    elif choice == "5":
        full_recon(target_domain)
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    print("[+] Finished.")

if __name__ == "__main__":
    main()
