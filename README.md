# VirusTotal-API-V3
Uses VirusTotal API V3 for basic search functionalities
VirusTotal Public API constraints and restrictions

The Public API is limited to 500 requests per day and a rate of 4 requests per minute

**IMPORTANT**: edit the python file and put your own api key
headers = {
    "accept": "application/json",
    "x-apikey": "**put your api key between the double quotes**"
}

**Example Usage:**

PS D:\virustotal> python.exe .\virustotalapi.py
Search files, URLs, domains, IPs and tag comments:
A9DE3F84F861EFA77C7082CFF0C1AE9BFE305194CA67548EB4FDE8EB00444DCA

🟡 NO DATA FOUND

 press ENTER to exit
PS D:\virustotal> python.exe .\virustotalapi.py
Search files, URLs, domains, IPs and tag comments:
google.com
🟢 CLEAN

Malicious:  0
Undetected:  10

 press ENTER to exit
PS D:\virustotal> python.exe .\virustotalapi.py
Search files, URLs, domains, IPs and tag comments:
f1a5a1187624fcf1a5804b9a15a4734d9da5aaf6
🔴 MALICIOUS

Malicious:  29
Undetected:  39
