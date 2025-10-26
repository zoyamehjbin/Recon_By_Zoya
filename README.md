# Recon_By_Zoya
REcon_By_Zoya automates subdomain discovery by combining passive data collection with active scanning
Passive Subdomain Enumeration

Gathers subdomains from public sources such as crt.sh, RapidDNS, AlienVault (OTX), HackerTarget, URLScan, Jldc, Google and Bing.

Runs subfinder to pull additional results from its providers.

# Active Subdomain Enumeration

Performs DNS brute-forcing with puredns using your wordlists to discover hidden subdomains.

Generates permutation variants of discovered names with gotator to find likely misspellings or variants.

Resolves permutation results back to IPs using puredns.

Probes SSL/TLS endpoints with cero to reveal hosts exposed via certificates.

# Optional JavaScript Scraping

Crawls target sites with gospider to collect JavaScript files and URLs.

Extracts domain names from those assets using unfurl (with a regex fallback).

Resolves any newly found domains with puredns.

# Finalizing results

Removes duplicates and writes a cleaned list to filtered_subs.txt.

Uses httpx to determine live hosts for the filtered subdomains and saves them to filtered_hosts.txt.

# Requirements & setup

Install the external tools used by the script (subfinder, puredns, gotator, cero, gospider, unfurl, httpx, etc.).

Clone the required wordlists repository into the expected Wordlists/ path.

Create subs/inscope.txt and add your target domain(s).

give command: chmod +x requirements.txt

give command: chmod +x Recon_by_zoya.py

Run the script after setup to automate thorough subdomain enumeration using a mixed passive + active approach.
