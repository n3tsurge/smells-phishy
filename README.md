# Smells Phishy
A Powershell tool for assessing phishing emails

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
•  hXXp[:]//www[.]arifleet[.]com/publications/pool_vehicles/
•  hXXps[:]//hatimedia[.]com/wp-content/plugins/wp[.]admin/secure[.]outloo[.]jdjksajkfdkfjdnffkjdsafkjAKKFDKFJDKFJKDF/ac90c11a260d0bbcf2c15b3e64198dd9/
Domains
•  www[.]arifleet[.]com
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
