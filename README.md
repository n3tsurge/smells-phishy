# Smells Phishy
A Powershell tool for assessing phishing emails

## WORK IN PROGRESS
I am not responsible if you wedge your system using this.

## Process

1. Smells phishy logs into your phishing reporting mailbox
2. It thanks the user for their submission (configurable in config.json)
3. The script extracts all the observables, IPs, Emails, URLs, Domains, Attachments and runs them against reputation based tools
4. The script gives the email a score out of 100 and sends a report to the designated security analyst.

## New Features:

•	Checks SentinelOne to see if the recipient has AV installed
•	Searches SentinelOne Deep Visibility for IOC hits and shares them in the e-mail report

## Features/Detections:

-	Extracts all URLs, Domains, IPs, Emails, File hashes (MD5, SHA1, SHA256)
-	Checks all emails against HaveIBeenPwned
-	Newly Registered Domain detection
-	Recently updated domain detection
-	Free CA detection (usage of LetsEncrypt for example)
-	VirusTotal detection for all:
    - File Hashes
    - URLS
    - Domains
-	Detects tracking pixels
-	Detects Base Striker attacks
-	Detects Executive spoofing
-	Detects suspicious subjects
-	Detects suspicious phrases
-	Detects suspicious patterns
-	Detects subject encoding
-	Detects Gmail protection methods as an indicator
-	Detects URL shorteners
    - Will unwrap shortened URLs to find the true destination
-	Detects rewrapped URLs
    - Will unwrap the wrapped URls too find the true destination
-	Detects Reply To mistmatches
-	Screenshots all URLs for a snapshot of what the site looks like

## Coming Soon

-	DMARC/DKIM validation
-	Parallel processing of e-mails
- Wild Fire integration


## Installation

1. Create a phishing mailbox for users to send mail to
2. Install the Microsoft Exchange Web Services API
3. Modify the config.sample.json file and name it config.json
4. Add your logo as `logo.png`
5. Modify the `Thank You.html` file with your message
6. Run `Check-PhishingReport.ps1`
7. Profit

## Sample Report

```
Smells Phishy Email Report
Score: 10/100
Message Details
Observables
URLs
•  hXXps[:]//hatimedia[.]com/wp-content/plugins/wp[.]admin/secure[.]outloo[.]jdjksajkfdkfjdnffkjdsafkjAKKFDKFJDKFJKDF/ac90c11a260d0bbcf2c15b3e64198dd9/
Domains
•  hatimedia[.]com
Hashes
•  42883ED4AFA0FA0BE84A3214E271F8D3
Suspicious Subject
•  Account Deactivation
•  Incident #748892
Suspicious Phrases
Suspicious Patterns
Screenshots
 
 
```
