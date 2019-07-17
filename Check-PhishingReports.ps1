$scriptPath = Split-Path -parent $PSCommandPath

$config = Get-Content .\config.json -Raw | ConvertFrom-JSON

# Create the analysis folder, ignore the error if it already exists
New-Item -ErrorAction Ignore -ItemType directory -Path $scriptPath"/Analysis"

$VTApiKey = $config.VirusTotal.ApiKey
$DomainWhitelist = $config.DomainWhitelist | ForEach-Object { $_.ToString() }

# Default Request Params
$DefaultRequestParams = @{}
$DefaultRequestParams.Add('ContentType', 'application/json')
if($config.ProxyUseDefaultCredentials) {
    $DefaultRequestParams.Add('ProxyUseDefaultCredentials', $true)
}
if($config.Proxy) {
    $DefaultRequestParams.Add('Proxy', $config.Proxy)
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[!] Active Directory Powershell Module not available, skipping Executive Fraud checks."
    $config.ExecutiveCheck = $false
}

$suspicious_patterns = @(
    '(blocked\ your?\ online)',
    '(suspicious\ activit)',
    '(updated?\ your\ account\ record)',
    '(Securely\ \S{3,4}\ one(\ )?drive)',
    '(Securely\ \S{3,4}\ drop(\ )?box)',
    '(Securely\ \S{3,4}\ Google\ Drive)',
    '(sign\ in\S{0,7}(with\ )?\ your\ email\ address)',
    '(Verify\ your\ ID\s)',
    '(dear\ \w{3,8}(\ banking)?\ user)',
    '(chase\S{0,10}\.html")',
    '(\b(?<=https?:\/\/)(www\.)?icloud(?!\.com))',
    '((?<![\x00\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A])appie\W)',
    '(\/GoogleDrive\/)',
    '(\/googledocs?\/)',
    '(\/Dropfile\/)',
    '(limit\ (and\ suspend\ )?your\ account)',
    '(\b(?<=https?:\/\/)(?!www\.paypal\.com\/)\S{0,40}pa?y\S{0,2}al(?!\S*\.com\/))',
    '(sitey\.me)',
    '(myfreesites\.net)',
    '(\/uploadfile\/)',
    '(\/\S{0,3}outloo\S{0,2}k\S{1,3}\W)',
    '(\b(?<=https?:\/\/webmail\.)\S{0,40}webmail\w{0,3}(?!\/[0-9])(?!\S{0,40}\.com\/))',
    '(owaportal)',
    '(outlook\W365)',
    '(\/office\S{0,3}365\/)',
    '(-icloud\Wcom)',
    '(pyapal)',
    '(\/docu\S{0,3}sign\S{1,4}\/)',
    '(\/helpdesk\/)',
    '(pay\Sa\S{0,2}login)',
    '(\/natwest\/)',
    '(\/dro?pbo?x\/)',
    '(%20paypal)',
    '(\.invoice\.php)',
    '(security-?err)',
    '(\/newdropbox\/)',
    '(\/www\/amazon)',
    '(simplefileupload)',
    '(security-?warning)',
    '(-(un)?b?locked)',
    '(\/\/helpdesk(?!\.))',
    '(\.my-free\.website)',
    '(mail-?update)',
    '(\.yolasite\.com)',
    '(\/\/webmail(?!\.))',
    '(\.freetemplate\.site)',
    '(\.sitey\.me)',
    '(\.ezweb123\.com)',
    '(\.tripod\.com)',
    '(\.myfreesites\.net)',
    '(mailowa)',
    '(-icloud)',
    '(icloud-)',
    '(contabo\.net)',
    '(\.xyz)',
    '(ownership\ validation\ (has\ )?expired)',
    '(icloudcom)',
    '(\w\.jar(?=\b))',
    '(\/https?\/www\/)',
    '(\.000webhost(app)?\.com)',
    '(is\.gd\/)',
    '(\.weebly\.com)',
    '(\.wix\.com)',
    '(tiny\.cc)',
    '(\.joburg)',
    '(\.top)',
    '(\/wp-admin\/)',
    '(OWA\/index.php)',
    '(Outlook(\ Web)?\ Access)'
)

$suspicious_phrases = @(
    "(word must be installed)",
    "(prevent further unauthorized)",
    "(prevent further unauthorised)",
    "(informations has been)",
    "(fallow our process)",
    "(confirm your informations)",
    "(failed to validate)",
    "(unable to verify)",
    "(delayed payment)",
    "(activate your account)",
    "(Update your payment)",
    "(submit your payment)",
    "(via Paypal)",
    "(has been compromised)",
    "(FRAUD NOTICE)",
    "(your account will be closed)",
    "(your apple id was used to sign in to)",
    "(was blocked for violation)",
    "(urged to download)",
    "(that you validate your account)",
    "(multiple login attempt)",
    "(trying to access your account)",
    "(suspend your account)",
    "(restricted if you fail to update)",
    "(informations on your account)",
    "(update your account information)",
    "(update in our security)",
    "(Account Was Limited)",
    "(verify and reactivate)",
    "(microsoft outlook windows update)",
    "(dear colleague)",
    "(please click here)",
    "(your statement is attached)",
    "(remit payment)",
    "(Dear Colleague)",
    '(Outlook(\ Web)?\ Access)'
)

$suspicious_subjects = @(
    "(has\ been\ limited)",
    "(We\ have\ locked)",
    "(has\ been\ suspended)",
    "(unusual\ activit[^*\s]+)",
    "(notifications\ pending)",
    "(your\ (customer\ )?account\ has)",
    "(your\ (customer\ )?account\ was)",
    "(new voice(\ )?mail)",
    "(Periodic\ Maintenance)",
    "(refund\ not\ approved)",
    "(account\ (is\ )?on\ hold)",
    "(wire\ transfer)",
    "(secure\ update)",
    "(temporar(il)?y\ deactivated)",
    "(verification\ required)",
    "(microsoft\ outlook)",
    "(account\ deactivation)",
    "(Incident\s\#\d+)",
    "(https?\:\/\/)",
    '(Outlook(\ Web)?\ Access)'
)

function Get-NewMessages {
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        $Mailbox
    )
    
    begin {
        Import-Module $config.Exchange.WebServiceDLL
    }
    
    process {
        
        # Build a connection the Exchange Server
        $ExchangeService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP1)
        $ExchangeService.Credentials = New-Object System.Net.NetworkCredential($config.SourceMailbox.username, $config.SourceMailbox.password)
        $ExchangeService.Url = $config.Exchange.WebServiceURL

        # Find the Inbox for the Phishing Mailbox
        $folderid = new-object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox,$Mailbox)     
        $Inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($ExchangeService,$folderid)
        
        # Define a filter to only grab unread items
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(10)
        $SearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::IsRead, $false)
        
        # Search the Inbox for unread items
        $Items = $Inbox.FindItems($searchFilter, $view)
        $itemCount = $Items.TotalCount

        if($itemCount -eq 0) {
            Write-Log -Message "No emails found. Exiting..."
            return
        } else {
            Write-Log -Message "Found $itemCount Emails. Processing..."
        }

        $Items | ForEach-Object { 

            $scanDate = Get-Date

            $_.Load()

            $threatScore = 0

            # Grab all the potential details about all the e-mail attachments
            if($_.HasAttachments) {

                # Create a new GUID for this item
                $guid = (New-GUID).Guid

                # Create a folder to store all the items in and do some analysis
                $workPath = $scriptPath+"/Analysis/"+$guid
                New-Item $workPath -Type Directory | Out-Null
                New-Item $workPath"/Attachments" -Type Directory | Out-Null
                New-Item $workPath"/Screenshots" -Type Directory | Out-Null
                New-Item $workpath"/ThreatData" -Type Directory | Out-Null

                $indicators = @();
                $threatHunt = @();

                $observables = @{
                    'ips' = @();
                    'hashes' = @();
                    'attachments' = @();
                    'urls' = @();
                    'domains' = @();
                    'subjects'= @();
                    'addresses' = @();
                    'pattern_matches' = @();
                    'phrase_matches' = @();
                    'subject_matches' = @();
                    'shorteners' = $false;
                    'rewrapped' = $false;
                    'reply_to_mismatch' = $false;
                    'tracking_pixel' = $false;
                    'base_striker' = $false;
                    'bitcoin_wallet' = $false;
                }

                # Thank the user for their submission
                if($config.SourceMailbox.send_thank_you) { Send-ThankYou -MailTo $_.Sender.Address -Service $ExchangeService }

                # Load all the attachemnts
                $_.Attachments.Load()

                # For every attachment extract the observables
                ForEach ($attachment in $_.Attachments) {
                    $observables = Invoke-ExtractObservables -Attachment $attachment -Observables $observables -Guid $guid                    
                }

                # Start scoring the email
                # Tally if there were any phrases matched
                if($observables.phrase_matches.Count -gt 0) {
                    $threatScore += $config.Scoring.phrase_weight*$observables.phrase_matches.Count
                }

                # Tally if there were any patterns matched
                if($observables.pattern_matches.Count -gt 0) {
                    $threatScore += $config.Scoring.pattern_weight*$observables.pattern_matches.Count
                }

                # Tally if there were subject subject patterns matched
                if($observables.subject_matches.Count -gt 0) {
                    $threatScore += $config.Scoring.subject_weight*$observables.subject_matches.Count
                }

                # Tally if a Gmail defang tag was observed
                if($observables.gmail_defang.Count -gt 0) {
                    $message = "A Gmail URL rewrap was observed"
                    $indicators += $message
                    $threatScore += 10
                }

                # Tally if the reply-to address does not match the original sender
                if($observables.reply_to_mismatch) {
                    $message = "The reply-to address does not match the original sender"
                    $indicators += $message
                    $threatScore += 10
                }

                # Score Email Addresses
                if($observables.addresses.Count -gt 0) {
                    ForEach($address in $observables.addresses) {
                        if($config.HaveIBeenPwned.Enabled) {
                            Write-Log -Message "Checking $address against HaveIBeenPwned"
                            $result = Get-HIBPStatus -EmailAddress $address
                            if($result) {
                                $message = "Email Address $(Defang $address) has been listed on HaveIBeenPwned"
                                Write-Log -Message $message -ForeGroundColor Yellow
                                $indicators += $message
                                $threatScore += ($result | Measure-Object).Count * $config.Scoring.email_address_weight
                            }
                        }
                    }
                }

                # Score Domains
                if($observables.domains.Count -gt 0) {
                    ForEach($domain in $observables.domains) {
                        if($config.Sucuri.Enabled) {
                            Write-Log -Message "Checking $domain against Sucuri Sitecheck"
                            $result = Get-SucuriScanReport -URL $domain
                            if($result.blacklisted -eq $true) {
                                $message = "The URL $(Defang $domain) is blacklisted on Sucuri Sitecheck" 
                                Write-Log -Message $message -ForeGroundColor Red 
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                            if($result.infected -eq $true) {
                                $message = "The URL $(Defang $domain) is infected on Sucuri Sitecheck"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                        }
                        if($config.JSONWhois.Enabled) {
                            Write-Log -Message "Performing a WHOIS check for $domain"
                            $result = Invoke-AnalyzeWhois -Domain $domain
                            if($result.new_registration) {
                                $message = "$(Defang $domain) was registered in the last $($config.JSONWhois.NewlyRegisteredDays) days"
                                Write-Log -Message $message -ForeGroundColor Yellow
                                $indicators += $message
                                $threatScore += $config.Scoring.whois_weight
                            }
                            if($result.recent_update) {
                                $message = "$(Defang $domain) was updated in the last $($config.JSONWhois.RecentUpdateDays) days"
                                Write-Log -Message $message -ForeGroundColor Yellow
                                $indicators += $message
                                $threatScore += $config.Scoring.whois_weight
                            }
                        }
                    }
                }

                # Score IPs
                if($observables.ips.Count -gt 0) {
                    ForEach($ip in $observables.ips) {
                        if($config.VirusTotal.Enabled) {
                            $result = Get-VTIPReport -IpAddress $ip
                            if($result.positives -ge $config.VirusTotal.PositiveThreshold) {
                                $message = "IP Address $(Defang $ip) has positive findings within the VirusTotal Positive Threshold ($($config.VirusTotal.PositiveThreshold))"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.ip_weight
                            }
                        }
                        if($config.AbuseDB.Enabled) {
                            $result = Get-AbuseDBCheck -ipAddress $ip
                            if($result.abuseConfidenceScore -ge $config.AbuseDB.confidenceThreshold) {
                                $message = "IP Address $(Defang $ip) has a high abuse confidence ($($result.abuseConfidenceScore)/100) on AbuseDB"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.ip_weight
                            }

                            if($result.totalReports -ge $config.AbuseDB.reportThreshold) {
                                $message = "IP Address $(Defang $ip) exceeds the report threshold of $($config.AbuseDB.reportThreshold) with $($result.totalReports) on AbuseDB"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.ip_weight
                            }
                        }
                    }
                }

                # Score URLs
                if($observables.urls.Count -gt 0) {
                    ForEach($url in $observables.urls) {
                        if($config.VirusTotal.Enabled) {
                            $result = Get-VTURLReport -URL $url
                            if($result.positives -ge $config.VirusTotal.PositiveThreshold) {
                                $message = "The URL $(Defang $url) has positive findings within the VirusTotal Positive Threshold ($($config.VirusTotal.PositiveThreshold))" 
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                        }
                        if($config.URLScan.Enabled) {
                            $result = Get-URLScanReport -URL $url
                            if($result.stats.malicious -gt $config.URLScan.MaliciousThreshold) {
                                $message = "The URL $(Defang $url) has a malicious indicators within the URLScan Malicious Threshold  ($($config.URLScan.MaliciousThreshold))"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                            Get-URLScanScreenshot -URL $result.task.screenshotURL -OutPath $workPath"/Screenshots/"
                        }
                        if($config.PhishTank.Enabled) {
                            Write-Log -Message "Checking $url against the PhishTank database"
                            $result = Get-PhishTankStatus -URL $url
                            if($result) {
                                $message = "The URL $(Defang $url) was found in the PhishTank database"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                        }
                        if($config.Certly.Enabled) {
                            Write-Log -Message "Checking $url against the Certly database."
                            if(Get-CertlyStatus -URL $url) {
                                $message = "The URL $(Defang $url) was found as not clean by Certly"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.url_weight
                            }
                        }
                    }
                }

                # Score Hashes
                if($observables.hashes.Count -gt 0) {
                    ForEach($hash in $observables.hashes) {
                        # Only submit SHA256 hashes to VT
                        if($config.VirusTotal.Enabled -and $hash.Length -eq 64) {
                            $result = Get-VTHashReport -Hash $hash
                            if($result.positives -ge $config.VirusTotal.PositiveThreshold) {
                                $message ="The hash $hash has positive findings within the VirusTotal Positive Threshold ($($config.VirusTotal.PositiveThreshold))"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                                $threatScore += $config.Scoring.hash_weight
                            }
                        }
                    }
                }

                # Score if any of the URLs were rewrapped or shortened
                if($observables.shortened) {
                    $indicators += "Shortend URLS were detected."
                    $threatScore += 5
                }

                if($observables.rewrapped) {
                    $indicators += "Websense wrapped URLs were detected indicating suspicious destinations."
                    $threatScore += 10
                }

                if($observables.tracking_pixel) {
                    $indicators += "A tracking pixel was detected"
                    $threatScore += 5
                }

                if($observables.executive_fraud) {
                    $indicators += "Potential Executive Fraud - Email uses Executive's name but different email"
                    $threatScore += 10
                }

                if($observables.base_striker) {
                    $indicators += "Potential Base Striker attack - HTML base tag detected"
                    $threatScore += 10
                }

                if($observables.bitcoin_wallet) {
                    $indicators += "Potential bitcoint wallet address detected"
                    $threatSCore += 15
                }

                # threatScore can't be greater than 100
                if($threatScore -gt 100) {
                    $threatScore = 100
                }

                if($observables.encoded_subject) {
                    $indicators += "Subject is encoded which can be used to evade detections"
                    $threatScore += 5
                }

                if($config.SentinelOne.Enabled) {
                    foreach($address in $observables.addresses) {
                        $username = Get-ADUsernameByEmail -Email $address
                        if($username) {
                            Write-Log -Message "Checking Anti-Virus status for user $username"
                            $missingAV = $null -eq (Get-S1HostByUsername -Username $username).data
                            if ($missingAV) {
                                $message = "User $username appears to be missing Anti-Virus"
                                Write-Log -Message $message -ForeGroundColor Red
                                $indicators += $message
                            }
                        }
                    }

                    # Internal users should have been removed from the observables list so we have to check
                    # against the person that reported the email to the phishing mailbox
                    $username = Get-ADUsernameByEmail -Email $_.Sender.Address
                    if($username) {
                        Write-Log -Message "Checking Anti-Virus status for user $username"
                        $missingAV = $null -eq (Get-S1HostByUsername -Username $username).data
                        if ($missingAV) {
                            $message = "User $username appears to be missing Anti-Virus"
                            Write-Log -Message $message -ForeGroundColor Red
                            $indicators += $message
                        }
                    }
                }

                if($config.SentinelOne.DeepVisibility) {
                    # Run a search for all domains in Deep Visibility
                    foreach($ip in $observables.ips) {
                        Write-Log -Message "Performing IOC hunt for $ip"
                        $hits = Get-S1DeepVisibilityHits -Indicator $ip -iocType "ip" -workPath $workPath
                        if($hits -gt 0) {
                            $threatHunt += "Observed users hitting the $(Defang $ip) indicator $hits times"
                        }
                    }

                     # Run a search for all domains in Deep Visibility
                    foreach($domain in $observables.domains) {
                        Write-Log -Message "Performing IOC hunt for $domain"
                        $hits = Get-S1DeepVisibilityHits -Indicator $domain -iocType "domain" -workPath $workPath
                        if($hits -gt 0) {
                            $threatHunt += "Observed users making a DNS request for $(Defang $domain) $hits times"
                        }
                    }

                    # Run a search for all urls in Deep Visibility
                    foreach($url in $observables.urls) {
                        Write-Log -Message "Performing IOC hunt for $url"
                        $hits = Get-S1DeepVisibilityHits -Indicator $url -iocType "url" -workPath $workPath
                        if($hits -gt 0) {
                            $threatHunt += "Observed users hitting the url $(Defang $url) $hits times"
                        }
                    }

                    # Run a search for all md5 in Deep Visibility
                    if($config.SentinelOne.Enabled) {
                        foreach($hash in $observables.hashes) {
                            Write-Log -Message "Performing IOC hunt for $hash"
                            if($hash.Length -eq 32) { $iocType = "md5" }
                            if($hash.Length -eq 40) { $iocType = "sha1" }
                            if($hash.Length -eq 128) { $iocType = "sha256" }

                            # Ignore SSDEEP hashes - SentinelOne doesn't support it
                            if($hash -notcontains ":") {
                                $hits = Get-S1DeepVisibilityHits -Indicator $hash -iocType $iocType -workPath $workPath
                            }
                            if($hits -gt 0) {
                                $threatHunt += "Observed users hitting the $(Defang $hash) indicator $hits times"
                            }
                        }
                    }

                    if($config.SentinelOne.SaveDVResults) {
                        # Compress all the threat data results and attached them as a zip file to the email
                        Compress-Archive -Path $workPath"/ThreatData" -CompressionLevel Optimal -Destination $workPath"/threatdata.zip"
                    }
                }

                if($config.Report.SendReport) {
                    $report = "<h1>Smells Phishy Email Report</h1>"

                    $report += "<h2>Score: $threatScore/100</h2>"
                    $report += "<h2>Message Details</h2>"
                    $report += "<b>Reported By:</b> $($_.Sender.Address)<br>"
                    $report += "<b>Subject:</b> $($_.Subject)<br>"
                    $report += "<b>Scan Start:</b> $scanDate<br>"
                    $report += "<b>Scan Finish:</b> $(Get-Date)<br>"

                    $report += "<h2>Scoring Indicators</h2>"
                    ForEach($indicator in $indicators) {
                        $report += "<li>$indicator</li>"
                    }

                    $report += "<h2>IOC hits</h2>"
                    ForEach($hunt in $threatHunt) {
                        $report += "<li>$hunt</li>"
                    }

                    $report += "<h2>Observables</h2>"
                    $report += "<h3>IP Addresses</h3>"
                    ForEach($ip in ($observables.ips | Select-Object -Uniq)) {
                        $ip = Defang $ip
                        $report += "<li>$ip</li>"
                    }

                    $report += "<h3>Subjects</h3>"
                    ForEach($subject in ($observables.subjects | Select-Object -Uniq)) {
                        $report += "<li>$subject</li>"
                    }

                    $report += "<h3>URLs</h3>"
                    ForEach($url in ($observables.urls | Select-Object -Uniq)) {
                        $url = Defang $url
                        $report += "<li>$url</li>"
                    }

                    $report += "<h3>Domains</h3>"
                    ForEach($domain in ($observables.domains | Select-Object -Uniq)) {
                        $domain = Defang $domain
                        $report += "<li>$domain</li>"
                    }

                    $report += "<h3>Email Addresses</h3>"
                    ForEach($address in ($observables.addresses | Select-Object -Uniq)) {
                        $address = Defang $address
                        $report += "<li>$address</li>"
                    }

                    $report += "<h3>Hashes</h3>"
                    ForEach($hash in ($observables.hashes | Select-Object-Object -Uniq)) {
                        $report += "<li>$hash</li>"
                    }

                    $report += "<h3>Suspicious Subject</h3>"
                    ForEach($subject in ($observables.subject_matches | Select-Object-Object -Uniq)) {
                        $report += "<li>$subject</li>"
                    }

                    $report += "<h3>Suspicious Phrases</h3>"
                    ForEach($phrase in ($observables.phrase_matches | Select-Object-Object -Uniq)) {
                        $report += "<li>$phrase</li>"
                    }

                    $report += "<h3>Suspicious Patterns</h3>"
                    ForEach($pattern in ($observables.pattern_matches | Select-Object -Uniq)) {
                        $report += "<li>$pattern</li>"
                    }

                    $report += "<h3>Screenshots</h3>"

                    if($config.SentinelOne.SaveDVResults) {
                        Send-Report -MailTo $config.Report.Recipient -Report $report -EmailSubject $_.Subject -Service $ExchangeService -ScreenshotsPath $workPath"/Screenshots/" -ThreatDataFile $workPath"/threatdata.zip"
                    } else {
                        Send-Report -MailTo $config.Report.Recipient -Report $report -EmailSubject $_.Subject -Service $ExchangeService -ScreenshotsPath $workPath"/Screenshots/"
                    }

                    # Compress all artifacts of the analysis
                    Compress-Archive -Path $workPath -CompressionLevel Optimal -Destination "$scriptPath/Analysis/$guid.zip"
                    Remove-Item $workPath -Recurse
                }

                if($config.SourceMailbox.mark_as_read) {
                    $_.IsRead = $true
                }
                $_.Update(1)

            } else {
                # TODO: Send the user a message saying they submitted the phishing report wrong
                Write-Log -Message "No e-mails found that can be processed."
            }

            # TODO SCORING

            Write-Log -Message "`"$($_.Subject)`" has a score of $threatScore/100"
            Write-Log -message "---"
        }       
    }
    
    end {
    }
}

function Invoke-ExtractObservables {
    Param(
        [Microsoft.Exchange.WebServices.Data.Attachment]$Attachment,
        [Hashtable]$observables=$null,
        [string]$guid
    )

    # If the attachment is another message
    # Follow the rabbit down the hole
    
    $Attachment.Load()
    if($Attachment.Item) {
        $Message = $Attachment.Item

        # Extract IP Addresses from the Message Header
        $observables.ips += Invoke-ExtractIPs -Data $Message.InternetMessageHeaders

        # Extract URLs from the Message Body
        # Decode HTML encoded strings
        Add-Type -AssemblyName System.Web
        $BodyData = [System.Web.HttpUtility]::HtmlDecode($Message.Body)
        $observables.urls += Invoke-ExtractURLs -Data $BodyData
        
        # Check if any of the URLS were defanged by Gmail
        if($BodyData -match 'defang_data-saferedirecturl') {
            $observables.gmail_defang = $Matches.Count
            Write-Log -Message "Extracting google defanged URL"
            ForEach($url in $observables.urls) {
                if($url -match "^.*url\?hl\=\w+\&q=(.*)\&source") {
                    $observables.urls += $Matches[1]
                    $observables.urls = $observables.urls -ne $url
                }
            }
        }

        # Extract the email subject
        $observables.subjects += $Message.Subject
        
        # Extract all emails
        $observables.addresses += $Message.Sender.Address
        if($Message.ReplyTo.Count -gt 0) {
            $observables.addresses += $Message.ReplyTo.Address
        }
        $observables.addresses += Invoke-ExtractEmailAddresses -Data $BodyData
        $observables.addresses += Invoke-ExtractEmailAddresses -Data $Message.InternetMessageHeaders
        
        # Check the body for base-striker 
        $matches = (Select-String '(<base href.*)' -AllMatches -Input $message.Body.Text).Matches.Value
        if($matches.count -gt 0) {
            $observables.base_striker = $true
        }

        # Check the body for a bitcoin wallet address
        # Issue #12
        $Matches = (Select-String '^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$' -AllMatches -Input $message.Body.Text).Matches
        if($matches.Group.Count -ge 1) {
            $observables.bitcoin_wallet = $true
        }
        
        # Check the body for the existence of any tracking pixels
        $matches = (Select-String '(<img.*(?=.*?src="(.*?)")(?=.*?(width\=\"1\"))(?=.*?(height\=\"1\")))' -AllMatches -Input $message.Body.Text).Matches
        if($matches.Groups.Count -ge 4) {
            $observables.tracking_pixel = $true
        }
        
        # Check to see if any patterns are matched in the Message Body
        ForEach($pattern in $suspicious_patterns) {
            $matches = ((Select-String $pattern -AllMatches -Input $message.Body.Text).Matches.Value)
            if($matches.count -gt 0) {
                $observables.pattern_matches += $matches
            }
        }
        
        # Check the body against well know phrases
        ForEach($phrase in $suspicious_phrases) {
            $matches = ((Select-String $phrase -AllMatches -Input $message.Body.Text).Matches.Value)
            if($matches.count -gt 0) {
                $observables.phrase_matches += $matches
            }
        }
        
        # Check the subject against well know subjects
        # Check if the subject is encoded
        ForEach($subject in $suspicious_subjects) {
            $matches = ((Select-String $subject -AllMatches -Input $message.Subject).Matches.Value)
            if($matches.count -gt 0) {
                $observables.subject_matches += $matches
            }
        }
        
        # If the Message has any attachments, inspect those as well
        if($Message.HasAttachments) {
            $Attachments = $Message.Attachments
            $Attachments.Load()
            ForEach($attach in $Attachments) {
                $observables = Invoke-ExtractObservables -Attachment $attach -Observables $observables -Guid $guid
            }
        }
        
        # Check if the reply-to matches the original sender
        if($Message.From.Addess -ne $Message.ReplyTo.Address) {
            $observables.reply_to_mismatch = $true
        }
        
        # Check if the message headers have an encoded subject
        if($config.Checks.EncodedSubject) {          
            $matches = ((Select-String "ubject\:\s\=\?" -AllMatches -Input $Message.InternetMessageHeaders).Matches.Value)
            if($matches.count -gt 0) {
                $observables.encoded_subject = $true
            }
        }
        
        if($config.Checks.Executives) {
            $observables.executive_fraud = Invoke-CheckExecFraud -Email $Message.From
        }
        
    } else {

        $filePath = $scriptPath+"\Analysis\"+$guid+"\Attachments\"+$Attachment.Name
        $observables.attachments += $Attachment.Name
        $Attachment.Load($filePath)
        $observables.hashes += (Get-FileHash $filePath -Algorithm MD5).hash
        $observables.hashes += (Get-FileHash $filePath -Algorithm SHA1).hash
        $observables.hashes += (Get-FileHash $filePath -Algorithm SHA256).hash
        $observables.hashes += (Get-SSDeep $filePath)
        $observables.urls += Invoke-ExtractURLs -Data (Get-Content $filePath -Raw)
    }

    # Check if any of the URLs are Websense Rewrapped URLs
    # if they are find the URL that was rewrapped
    # Note: Only works with Websense
    Write-Log -Message "Checking for Websense wrapped URLs"
    ForEach($url in $observables.urls) {
        if($url -like "*webdefence.global.blackspider.com*") {
            Write-Log -Message "Discovered Websense wrapped URL $url, extracting final destination"

            # Extract the real URL from the page
            $observables.urls += Invoke-ExtractWrappedURL -WebsenseURL $url

            # Remove the Wrapper URL
            $observables.urls = $observables.urls | Where-Object { $_ -notcontains $url }

            $observables.rewrapped = $true
        }
    }
   
    Write-Log -Message "Checking for shortened URLs"
    # Check if any of the URLs are shortened
    ForEach($url in $observables.urls) {
        $data = Get-UnshortendURL $url
        if($data -ne $url) {
            Write-Log -Message "Discovered shortened URL $url, extracting final destination"

            # Add the real URL
            $observables.urls += $data

            # Remove the shortener
            $observables.urls = $observables.urls | Where-Object { $_ -notcontains $url }

            $observables.shorteners = $true
        }
    }

    # Remove any whitelisted domains from the list
    $filtered_urls = @()
    ForEach($url in $observables.urls) {
        $found = $false
        ForEach($domain in $DomainWhitelist) {
            $filter = "*"+$domain+"*"
            if($([System.URI]$url).Authority -like $filter) {
                $found = $true
            }
        }
        if(!$found) {
            $filtered_urls += ($url)
        }
    }


    
    # Remove any whitelisted domains from the addresses list
    $filtered_emails = @()
    ForEach($address in $observables.addresses) {
        $found = $false
        ForEach($domain in $DomainWhitelist) {
            $filter = "*"+$domain+"*"
            if($address -like $filter) {
                $found = $true
            }
        }
        if(!$found) {
            $filtered_emails += ($address)
        }
    }

    
    $observables.addresses = [array]($filtered_emails | Sort-Object | Select-Object -Uniq)

    $observables.urls = [array]($filtered_urls | Sort-Object | Select-Object -Uniq)

    # Dedup the URLs and extract the domains from the URLs
    $observables.urls = [array]($observables.urls | Sort-Object | Select-Object -Uniq)

    # Normalize all the slashes
    if($observables.urls.Count -gt 0) {
        $observables.urls = [array]($observables.urls.replace('(:(\/\/|\\\/|\/\\))','://'))
    }

    # Extract the domains from the URLs
    $observables.urls | ForEach-Object {
        # Add the domain if it isn't already in the list
        if($_ -like "*http*") {
            $domain = ([System.URI]$_).Authority
            if($observables.domains -notcontains $domain) {
                $observables.domains += ($domain)
            }            
        } else {
            # Some URLs don't have a protocol in the URI
            # add one so System.URI can do its job
            $domain = ([System.URI]$_).Authority
            if($observables.domains -notcontains $domain) {
                $observables.domains += ($domain)    
            }
        }
    }

    # Get domains from email addresses
    if($observables.addresses) {
        ForEach($address in $observables.addresses) {
            $domain = ($address -Split "@")[1]
            $observables.domains += $domain
        }
    }

    # Dedupe domains
    $observables.domains = [array]($observables.domains | Sort-Object | Select-Object -Uniq)

    # Resolve all the domains to their IP address
    if($observables.domains) {
        ForEach($domain in $observables.domains) {
            if($domain) {
                if($config.ResolveDomainsFromIP) {
                    $ip = try { (Resolve-DnsName $domain -ErrorAction SilentlyContinue).IP4Address  } catch { $null }
                    if($ip) { $observables.ips += $ip }
                }
            }
        }
    }

    # Dedupe IPs and Domains again
    $observables.ips = [array]($observables.ips | Sort-Object | Select-Object -Uniq)

    return $observables
}

# Defangs a URL, IP or Email so that automatic linking doesn't occur
function Defang {
    Param(
        [string]$data
    )

    process {
        $data = $data.Replace('http', 'hXXp')
        $data = $data.Replace('.','[.]')
        $data = $data.Replace(':', '[:]')
        $data = $data.Replace('@', '[@]')

        return $data
    }
}

function Send-Report {
    Param(
        [string]$MailTo,
        [string]$Report,
        [string]$EmailSubject,
        [string]$ScreenshotsPath,
        [string]$ThreatDataFile,
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$Service
    )

    $email = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage($Service)

    $email.Subject = "Phishing Report: $EmailSubject"

    # Add all the screenshots

    $screenshots = Get-ChildItem $ScreenshotsPath
    if($screenshots) {
        ForEach($screenshot in $screenshots) {
            $email.Attachments.AddFileAttachment($screenshot.Name, $ScreenshotsPath+$screenshot.Name) | Out-Null
            $Report += '<img width=600 height=600 style="width:2.2916in;height:1.2604in" id="'+$screenshot.Name+'" src="cid:'+$screenshot.Name+'" alt="cid:'+$screenshot.Name+'"><br>'
        }
        ForEach($attachment in $email.Attachments) {
            $attachment.IsInline = $true
            $attachment.ContentId = $attachment.Name
        }
    }

    if($ThreatDataFile) {
        $threatData = Get-ChildItem $ThreatDataFile
        $email.Attachments.AddFileAttachment($threatData.Name, $ThreatDataFile) | Out-Null
    }

    $email.body = $Report
    [void]$email.ToRecipients.Add($MailTo)

    $email.SendAndSaveCopy()

}

function Send-ThankYou {
    Param(
        [string]$MailTo,
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$Service,
        [switch]$Error
    )

    $email = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage($Service)

    $email.Subject = "Thank you for your Phishing submission"
    $email.body = Get-Content $scriptPath"\Thank You.html" -Raw
    [void]$email.ToRecipients.Add($MailTo)
    [void]$email.Attachments.AddFileAttachment("logo.png", $scriptPath+"\logo.png")
    $email.Attachments[0].IsInline = $true
    $email.Attachments[0].ContentId = "logo.png"

    $email.SendAndSaveCopy()

}

function Invoke-ExtractIPs {
    Param(
        [Parameter(Mandatory=$true)][string]$Data
    )

    $ip_regex = "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    $ips = ((Select-String $ip_regex -Input $data -AllMatches).Matches.Value)
    $ips = $ips | Select-Object -Uniq

    # Filter out RFC1918 addresses
    $ips = $ips | Where-Object { (!$_.StartsWith("192.168.") -and !$_.StartsWith("172.22.16.") -and !$_.StartsWith("10.") -and $_ -ne "127.0.0.1") }

    return $ips
}

function Invoke-ExtractURLs {
    Param(
        [Parameter(Mandatory=$true)][string]$Data
    )

    $pattern = "\b(https?|ftp|file|skype|slack):(\/\/|.*)(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)\b"
    #$pattern = "\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#\*/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\*/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\*/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\*/%=~_|$])

    $urls = ((Select-String $pattern -AllMatches -Input $Data).Matches.Value)
    $urls = $urls | Select-Object -Uniq
    return $urls
}

function Invoke-ExtractEmailAddresses {
    Param(
        [Parameter(Mandatory=$true)][string]$Data
    )

    $emails = ((Select-String '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'-AllMatches -Input $Data).Matches.Value)
    $emails = $emails | Select-Object -Uniq
    return $emails
}

function Invoke-ExtractWrappedURL {
    Param(
        [Parameter(Mandatory=$true)][string]$WebsenseURL
    )

    process {
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Uri', $WebsenseURL)
        $Data = Invoke-WebRequest @RequestParams

        $Data = [System.Web.HttpUtility]::HtmlDecode($Data)

        $url = ((Select-String 'URL:.*(\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#\*/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\*/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\*/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\*/%=~_|$]))' -AllMatches -Input $data).Matches.Groups[1].Value)
        return $url
    }
}

function Invoke-AnalyzeWhois {
    Param(
        [Parameter(Mandatory=$true)]$Domain
    )

    process {

        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://api.jsonwhois.io/whois/domain?key=$($config.JSONWhois.token)&domain=$($Domain)"
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('Method', 'GET')

        $data = Invoke-RestMethod @RequestParams

        $WhoisReport = $data.result

        $report = @{
            "new_registration" = $false;
            "recent_update" = $false;
        }

        # Get todays date so we can calculate if activity on the domain is recent
        $today = (Get-Date)

        if($WhoisReport.created) {
            if((New-TimeSpan -Start ([datetime]$WhoisReport.created) -End $today).TotalDays -le $config.JSONWhois.NewlyRegisteredDays) {
                $report.new_registration = $true
            }   
        }

        if($WhoisReport.changed) {
            if((New-TimeSpan -Start ([datetime]$WhoisReport.changed) -End $today).TotalDays -le $config.JSONWhois.RecentUpdateDays) {
                $report.recent_update = $True
            }
        }

        return $report
    }
}

function Get-SiteCertificate{
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$IP,
        [Parameter(Mandatory=$false)][string]$Port=443,
        [Parameter(Mandatory=$false)][switch]$Validate
    )

    Begin {
    }

    Process {

        # Skip sites that don't have the destination port open
        if(!(Test-NetConnection -ComputerName $IP -Port $tcp)) {
            return $null
        }
        
        try {
            $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
            $tcpSocket = New-Object System.Net.Sockets.TcpClient($IP, $Port)
            $tcpStream = $tcpSocket.GetStream()
            $callback = { param($sender, $cert, $chain, $errors) return $true }
            $sslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($tcpStream, $true, $callback)
            $sslStream.AuthenticateAsClient($IP)
            $certInfo = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        } finally {
            $sslStream.Dispose()
            $tcpClient.Dispose()
        }

        $report = @{
            recently_generated=$false;
            lets_encrypt=$false;
            verified=$false;
        }

        # If the cert was issued recently it may be a new site
        if((New-TimeSpan -Start ([datetime]$certInfo.NotBefore) -End $today).TotalDays -le 90) {
            $report.recently_generated = $true
        }

        # We sort of trust Let's Encrypt
        if($certInfo.Issuer -eq "CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US") {
            $report.lets_encrypt = $true
        }

        # Valid cert?
        if($certInfo.Verify()) {
            $report.verified = $true
        }

        return $report

    }

    End {
    }
}

<# 
# For Futute consideration to check DNS records for
# the sending mail server
Function Validate-DNSRecords {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$domain
    )

    Begin {
    }

    Process {

        $report = @{
            spfRecord = $false;
            spfIndicators = @{
                softFail = $false;
                allowAll = $false;
                broadRange = $false;
                neutral = $false
            };
            dmarcRecord = $false;
            dkimRecord = $false;
        }

        $records = Resolve-DnsName $domain -Type TXT -Server 8.8.8.8
        ForEach($record in $records) {
            if($record.Strings -like "v=spf*") {
                $report.spfRecord = $true
                if($record.Strings -like "*+all") {
                    $report.spfIndicators.allowAll = $true
                }

                if($record.Strings -like "*\?all") {
                    $report.spfIndicators.neutral = $true
                }

                if($record.Strings -like "*~all") {
                    $report.spfIndicators.softFail = $true
                }

                if($record.Strings -like "*ip4*") {
                    $ipCount = 0
                    $matches = (Select-String 'ip4:([^*\s]+)' -Input $record.Strings -AllMatches).Matches
                    ForEach($match in $matches) {
                        $match.Groups[1].Value
                    }
                }

            }

            if($record.Strings -like "v=DMARC1*") {
                $report.dmarcRecord = $true
            }
        }

        $report = New-Object -Type PSObject -Property $report
        return $report
    }

    End {
    }
} #>

function Get-VTDomainReport {
    Param(
        [Parameter(Mandatory=$true)][string]$Domain
    )

    process {

        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VTApiKey&domain=$Domain"
        $RequestParams.Add('Uri', $url)
        $result = Invoke-RestMethod @RequestParams 
        return $result

    }
}

function Get-VTIPReport {
    Param(
        [Parameter(Mandatory=$true)][string]$IpAddress
    )

    process {
        Write-Log -Message "Running Virus Total IP Report for $IpAddress"
        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$VTApiKey&resource=$IpAddress"
        $RequestParams.Add('Uri', $url)
        $result = Invoke-RestMethod @RequestParams
        return $result
    }
}

function Get-VTURLScan {
    Param(
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {
        Write-Log -Message "Running Virus Total scan for $URL"
        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://www.virustotal.com/vtapi/v2/url/scan?apikey=$VTApiKey&resource=$URL"
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('Method', 'POST')
        $result = Invoke-RestMethod @RequestParams
        return $result
    }
}

function Get-VTURLReport {
    Param(
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {
        Write-Log -Message "Checking Virus Total score for $URL"
        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://www.virustotal.com/vtapi/v2/url/report?apikey=$VTApiKey&resource=$URL"
        $RequestParams.Add('Uri', $url)
        $result = Invoke-RestMethod @RequestParams
        return $result
    }
}

function Get-VTHashReport {
    Param (
        [Parameter(Mandatory=$true)][string]$Hash   
    )
    process {
        Write-Log -Message "Checking Virus Total score for $hash"
        $RequestParams = $DefaultRequestParams.Clone()
        $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$VTApiKey&resource=$Hash"
        $RequestParams.Add('Uri', $url)
        $result = Invoke-RestMethod @RequestParams
        return $result
    }

}

function Get-URLScanScreenshot {
    Param(
        [Parameter(Mandatory=$true)][string]$URL,
        [string]$OutPath
    )

    process {

        $screenshotPath = $OutPath+(New-Guid).Guid+".png"

        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('OutFile', $screenshotPath)
        
        Invoke-RestMethod @RequestParams
    }
}

function Get-CertlyStatus {
    Param (
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {

        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Uri', "https://api.certly.io/v1/lookup?url=$URL&token=$($config.Certly.APIKey)")
        $RequestParams.Add('Method', 'Get')
        $RequestParams.Add('ErrorVariable', $RequestError)

        $result = try { $result = (Invoke-RestMethod @RequestParams).data } catch { $null }

        if(!$result) {
            return $false
        }

        return $result.status -ne "clean"
    }
}

function Get-URLScanReport {
    Param (
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {
        
        # Build a default Invoke-RestMethod Param object based on our config file
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Headers', @{'API-Key'=$config.URLScan.ApiKey})
        $RequestParams.Add('Method', 'POST')
        $RequestParams.Add('Body', (@{"url"=$url;} | ConvertTo-Json))
        $RequestParams.Add('Uri', "https://urlscan.io/api/v1/scan/")
        $RequestParams.Add('ErrorVariable', 'RESTError')

        # Search to see if the URL has already been scanned
        $result = Invoke-RestMethod @RequestParams
        if(!$RESTError) {
            Write-Log -Message "Sleeping for $($config.URLScan.ScanWait) seconds for URLScan report for $url"
            Start-Sleep $config.URLScan.ScanWait
            
            # Get the results of the scan
            $RequestParams.Method = 'GET'
            $RequestParams.Uri = $result.api
            $RequestParams.Remove('Body')
            $result = Invoke-RestMethod @RequestParams
            return $result    
        }

        return $null
        
    }
}

function Get-PhishTankStatus {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Method', 'Post')
        $RequestParams.Add('Uri', "http://checkurl.phishtank.com/checkurl/")
        $RequestParams.Add('Body', @{
                url=$URL;
                format="json";
                app_key=$config.PhishTank.APIKey
            })

        $result = Invoke-WebRequest @RequestParams
        return $result.results.in_database
    }
}

function Get-UnshortendURL {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {

        $shorteners = @(
            "bit.do",
            "t.co",
            "lnkd.in",
            "db.tt",
            "qr.ae",
            "adf.ly",
            "goo.gl",
            "bitly.com",
            "bit.ly",
            "cur.lv",
            "tinyurl.com",
            "ow.ly",
            "ity.im",
            "q.gs",
            "is.gd",
            "po.st",
            "bc.vc",
            "twitthis.com",
            "u.to",
            "j.mp",
            "buzurl.com",
            "cutt.us",
            "u.bb",
            "yourls.org",
            "x.co",
            "vzturl.com",
            "v.gd",
            "tr.im"
        )

        if($null -ne ($shorteners | Where-Object { ([System.URI]$URI).Authority -match $_ }))
        {
            $uri = "https://unshorten.me/s/$URL"
            $RequestParams = $DefaultRequestParams.Clone()
            $RequestParams.Add('Method', 'Get')
            $RequestParams.Add('Uri', $uri)

            $data = Invoke-RestMethod @RequestParams
            if($data -like "*Unknown Error*") {
                return $URL
            } else {
                return $data    
            }
        } else {
            return $URL
        }
        
    }
}

<# 
Grabs the SSDEEP hash of a file
#>
function Get-SSDeep {
    [Cmdletbinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$File
    )

    Begin {}

    Process {
        $hash = .\utilities\ssdeep\ssdeep.exe $File
        $hash = $hash.split("`r`n")[2]
        $hash = $hash.split(',')[0]    
    }

    End {
        return $hash
    }
}


function Get-SucuriScanReport {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$URL
    )

    process {
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Method', 'Get')
        $RequestParams.Add('Uri', "https://sitecheck.sucuri.net/results/$URL")
        $data = Invoke-WebRequest @RequestParams

        $siteInfected = $data.Content -notlike "*No Malware Detected*"
        $siteBlacklisted = $data.Content -notlike "*Site is not Blacklisted*"

        return @{"Infected"=$siteInfected;"Blacklisted"=$siteBlacklisted}
    }
}

<# 
Checks AbuseDB reports for an IP address
#>
function Get-AbuseDBCheck {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$ipAddress
    )

    Begin {
        $RequestParams = $DefaultRequestParams.Clone()
    }

    Process {
        $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ipAddress&maxAgeInDays=90"
        $RequestParams.Add('Method', 'Get')
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('Headers', @{ Key = $config.AbuseDB.token })
        $RequestParams.Add('ErrorVariable', 'RESTError')

        $result = Invoke-RestMethod @RequestParams
        return $result.data
    }
}

<# 
Checks the HaveIBeenPwned API to see if an email address has been
pwned at some point
#>
function Get-HIBPStatus {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$emailAddress
    )

    Begin {
        $RequestParams = $DefaultRequestParams.Clone()
    }

    Process {
        $url = "https://haveibeenpwned.com/api/v2/breachedaccount/{0}" -f $emailAddress
        $RequestParams.Add('Method', 'Get')
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('ErrorVariable', 'RESTError')

        $result = try { Invoke-RestMethod @RequestParams } catch { $null }
        return $result
    }
}

<# Grabs the last machine a user was logged into in
SentinelOne.  If no machine is found, a note is added in the analysis report
indicating as such.  If a machine is found a Deep visibility search is performed
to see if any users have clicked on any indicators
#>
function Get-S1HostByUsername {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$username
    )

    Begin {

        $url = "$($config.SentinelOne.TenantUrl)/web/api/v2.0/agents?lastLoggedInUserName__contains=$username&apitoken=$($config.SentinelOne.ApiKey)"
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Uri', $url)
        $RequestParams.Add('Method', 'GET')
        

    }

    Process {
        $result = Invoke-RestMethod @RequestParams
        $result
    }

    End {

    }
}

<# 
Searches SentinelOne Deep Visibility for indicators of compromise being
used by users
#>
function Get-S1DeepVisibilityHits {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$indicator,
        [Parameter(Mandatory=$true)][string]$iocType,
        [Parameter(Mandatory=$false)][string]$workPath
    )

    Begin {

        $apiToken = $config.SentinelOne.APIKey

        if($iocType -eq "domain") {
            $query = 'DnsRequest CONTAINS "'+$indicator+'" OR NetworkUrl CONTAINS "'+$indicator+'"'
        }
        if($iocType -eq "url") {
            $query = 'NetworkURL = "'+$indicator+'"'
        }
        if($iocType -eq "md5") {
            $query = 'FileMD5 = "'+$indicator+'"'
        }
        if($iocType -eq "sha1") {
            $query = 'FileMD5 = "'+$indicator+'"'
        }
        if($iocType -eq "sha256") {
            $query = 'FileMD5 = "'+$indicator+'"'
        }
        if($iocType -eq "ip") {
            $query = 'DstIp = "'+$indicator+'" OR SrcIp = "'+$indicator+'" OR DNSResponse CONTAINS "'+$indicator+'"'   
        }
    }

    Process {

        # Create the query body
        $fromDate = Get-Date -Hour 0 -Minute 00 -Second 00 -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'
        $toDate = Get-Date -Hour 23 -Minute 59 -Second 59 -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'

        $body = @{
             toDate = $toDate;
             fromDate = $fromDate;
             queryType = @("events");
             query = $query;
             tenant = $true;
             siteIds = @();
             groupIds = @();
        }

        $body = $body | ConvertTo-Json

        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('uri', "$($config.SentinelOne.TenantUrl)/web/api/v2.0/dv/init-query?apiToken=$apiToken")
        $RequestParams.Add('method', 'POST')
        $RequestParams.Add('body', $body)

        # Create the query
        $queryId = $null
        $result = Invoke-RestMethod @RequestParams
        if($result) { $queryId = $result.data.queryId }

        # Poll for query completion
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('uri', "$($config.SentinelOne.TenantUrl)/web/api/v2.0/dv/query-status?apiToken=$apiToken&queryId=$queryId")
        $RequestParams.Add('method', 'GET')

        $queryFinished = $false
        while(!$queryFinished) {
            $result = Invoke-RestMethod @RequestParams
            if ($result.data.responseState -eq "FINISHED") {
                $queryFinished = $true
                Start-Sleep 5;
            }
        }

        # Pull down the results
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('uri', "$($config.SentinelOne.TenantUrl)/web/api/v2.0/dv/events?apiToken=$apiToken&queryId=$queryId&limit=100")
        $RequestParams.Add('method', 'GET')
        $result = Invoke-RestMethod @RequestParams

        if($config.SentinelOne.SaveDVResults) {
            $data = $result.data
            if($result.pagination.nextCursor) {
                $nextCursor = $result.pagination.nextCursor
                $allData = $false
                while(!$allData) {
                    $RequestParams.Uri = "$($config.SentinelOne.TenantUrl)/web/api/v2.0/dv/events?apiToken=$apiToken&queryId=$queryId&cursor=$nextCursor&limit=100"
                    $result = Invoke-RestMethod @RequestParams
                    $data += $result.data
                    if(!$result.pagination.nextCursor) {
                        $allData = $true
                    } else {
                        $nextCursor = $result.pagination.nextCursor
                    }
                }
            } 

            if($data.Length -gt 0) { 
                $filename = "threat_hunt_"+$indicator.replace(".","_")+"_"+(Get-Date -UFormat "%Y%m%d")+".csv"
                $data | Export-CSV $workPath"/ThreatData/"$filename -NoTypeInformation 
            }
        }
    }

    End {
        return $result.pagination.totalItems
    }

}

<# Grabs a users active directory username by looking for their e-mail
address in AD.  Falls back to dsquery if the Powershell RSAT tools are not installed
#>
function Get-ADUsernameByEmail {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$email
    )

    Begin {
        $useDSQUERY = $false
        $username = $null

        $domains = @()
        ForEach($forest in $config.ADDomains) {
            $domains += (Get-ADForest $forest).domains
        }

        if(!(Get-Command Get-ADUser)) {
            Write-Log -Message "Powershell RSAT tools not installed, using DSQUERY"
            $useDSQUERY = $true
        }
    }

    Process {

        if($useDSQUERY) {
            # TODO: ADD THE DSQUERY ALTERNATIVE TO THE BELOW
        } else {
            $user = $null
            ForEach($domain in $domains) {
                $search = "*$email*"
                $user = Get-ADUser -Filter { proxyAddresses -like $search } -Properties proxyAddresses -Server $domain
                if($user) {
                    Write-Log -Message "Found username $($user.sAMAccountName) for $email in the $domain domain"
                    break
                }
            }
            $username = $user.sAMAccountName
        }
    }

    End {
        return $username
    }
}

<#
Checks if the e-mail is masquerading as a company executive
Executives are defined in the configuration file with their First, Last and Valid Email
Requires the Microsoft Active Directory Module
#>
function Invoke-CheckExecFraud {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$true)][string]$Email
    )

    Begin {

        $domains = @()
        ForEach($forest in $config.ADDomains) {
            $domains += (Get-ADForest $forest).domains
        }
    }

    Process {
        ForEach($exec in $config.Executives) {
            
            ForEach($domain in $domains) {
                $adUser = try { Get-ADUser -Filter { sAMAccountName -eq $exec } -Properties proxyAddresses -Server $domain } catch { $null }
                if($adUser) {
                    break;
                }
            }
            
            # If we found the user pull all their mail addresses else return False
            if($adUser) {
                $mailAddresses = $adUser.proxyAddresses | Where-Object { $_ -match 'smtp' } | ForEach-Object { ($_ -split ":")[1] }
            } else {
                return $false
            }            

            # If the email is using the executives first name and last name but the email isn't theirs return True
            if(($Email -match $adUser.givenName) -and ($Email -match $adUser.surname) -and ($Email -notmatch ($mailAddresses -join "|"))) {
                return $true
            }
        }
        return $false
    }

    End {
    }
}

function Write-Log {
    Param(
        [string]$Message,
        [string]$ForeGroundColor="White",
        [switch]$Verbose
    )

    process {
        $date = '{0:yyyy-MM-dd hh:mm:ss}' -f (Get-Date)
        Write-Host "[$date] $Message" -ForeGroundColor $ForeGroundColor
    }
    
}

function Write-ReportLog {
    Param(
        [string]$MailFrom,
        [string]$MailSubject
    )

    $date = '{0:yyyy-MM-dd hh:mm:ss}' -f (Get-Date)
    $logPath = "\\mtlwpplogxm01\c$\Logs\phishing_report.log" # TODO: MOVE THIS TO THE CONFIG FILE
    "DATE=$date | SENDER=$MailFrom | SUBJECT=$MailSubject" | Out-File $logPath -Append
    #Get-Content $logPath
    #exit
}

<# 
Checks Wildfire for information on a hash, if the hash is not available
it will submit the file if its in the approved extension list
#>
function Get-WildFireReport {
    Param(
        [Parameter(Mandatory=$true)][string]$apikey,
        [Parameter(Mandatory=$false)][string]$hash,
        [Parameter(Mandatory=$false)][string]$filePath
    )

    process {

        Write-Log -Message "Checking Wildfire score for $hash"
        $RequestParams = $DefaultRequestParams.Clone()
        $RequestParams.Add('Uri', 'https://wildfire.paloaltonetworks.com/publicapi/get/report')
        $RequestParams.Add('Method', 'POST')
        $RequestParams.Add('Body', @{'apikey'=$apikey;'hash'=$hash;'format'='xml'})
        $RequestParams.Remove('ContentType')
        #$result = Invoke-RestMethod @RequestParams
        #$result.wildfire.
    }
}

While (1) {
    Write-Log -Message "Polling target mailbox"
    Get-NewMessages -Mailbox $config.SourceMailbox.address
    Start-Sleep $config.SourceMailbox.polling_interval
}
