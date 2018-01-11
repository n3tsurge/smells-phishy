$scriptPath = Split-Path -parent $PSCommandPath

$config = Get-Content .\config.json -Raw | ConvertFrom-JSON

$VTApiKey = $config.VirusTotal.ApiKey
$VTPositiveThreshold = $config.VirusTotal.PositiveThreshold
$DomainWhitelist = $config.DomainWhitelist | % { $_.ToString() }

# Default Request Params
$DefaultRequestParams = @{}
$DefaultRequestParams.Add('ContentType', 'application/json')
if($config.ProxyUseDefaultCredentials) {
    $DefaultRequestParams.Add('ProxyUseDefaultCredentials', $true)
}
if($config.Proxy) {
    $DefaultRequestParams.Add('Proxy', $config.Proxy)
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
    '(\b(?<=https?://)(www\.)?icloud(?!\.com))',
    '((?<![\x00\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A])appie\W)',
    '(/GoogleDrive/)',
    '(/googledocs?/)',
    '(/Dropfile/)',
    '(limit\ (and\ suspend\ )?your\ account)',
    '(\b(?<=https?://)(?!www\.paypal\.com/)\S{0,40}pa?y\S{0,2}al(?!\S*\.com/))',
    '(sitey\.me)',
    '(myfreesites\.net)',
    '(/uploadfile/)',
    '(/\S{0,3}outloo\S{0,2}k\S{1,3}\W)',
    '(\b(?<=https?://webmail\.)\S{0,40}webmail\w{0,3}(?!/[0-9])(?!\S{0,40}\.com/))',
    '(owaportal)',
    '(outlook\W365)',
    '(/office\S{0,3}365/)',
    '(-icloud\Wcom)',
    '(pyapal)',
    '(/docu\S{0,3}sign\S{1,4}/)',
    '(/helpdesk/)',
    '(pay\Sa\S{0,2}login)',
    '(/natwest/)',
    '(/dro?pbo?x/)',
    '(%20paypal)',
    '(\.invoice\.php)',
    '(security-?err)',
    '(/newdropbox/)',
    '(/www/amazon)',
    '(simplefileupload)',
    '(security-?warning)',
    '(-(un)?b?locked)',
    '(//helpdesk(?!\.))',
    '(\.my-free\.website)',
    '(mail-?update)',
    '(\.yolasite\.com)',
    '(//webmail(?!\.))',
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
    '(/https?/www/)',
    '(\.000webhost(app)?\.com)',
    '(is\.gd/)',
    '(\.weebly\.com)',
    '(\.wix\.com)',
    '(tiny\.cc)',
    '(\.joburg)',
    '(\.top)',
    '(\/wp-admin\/)'
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
    "(Dear Colleague)"
)

$suspicious_subjects = @(
    "(has\ been\ limited)",
    "(We\ have\ locked)",
    "(has\ been\ suspended)",
    "(unusual\ activity)",
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
    "(Incident\s\#\d+)"
)


function Get-NewMessages {
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        $Mailbox
    )
    
    begin {
        Import-Module $config.ExchangeWebServicesDLL
    }
    
    process {

        Write-Log -Message "---"
        
        # Build a connection the Exchange Server
        $ExchangeService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP1)
        $ExchangeService.Credentials = New-Object System.Net.NetworkCredential($config.PhishingMailboxUsername, $config.PhishingMailboxPassword)
        $ExchangeService.Url = $config.ExchangeWebServiceURL

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
            exit
        } else {
            Write-Log -Message "Found $itemCount Emails. Processing..."
        }

        $Items | % { 

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

                $observables = @{
                    'ips' = @();
                    'hashes' = @();
                    'urls' = @();
                    'domains' = @();
                    'subjects'= @();
                    'addresses' = @();
                    'pattern_matches' = @();
                    'phrase_matches' = @();
                    'subject_matches' = @();
                }

                # Thank the user for their submission
                if($config.SendThankYou) { Send-ThankYou -MailTo $_.Sender.Address -Service $ExchangeService }

                # Load all the attachemnts
                $_.Attachments.Load()

                # For every attachment extract the observables
                ForEach ($attachment in $_.Attachments) {
                    $observables = Invoke-ExtractObservables -Attachment $attachment -Observables $observables -Guid $guid
                }

                # Deduplicate domains
                $observables.domains = $observables.domains | Select -Uniq

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

                # Score URLs
                if($observables.urls.Count -gt 0) {
                    ForEach($url in $observables.urls) {
                        if($config.VirusTotal.Enabled) {
                            $result = Get-VTURLReport -URL $url
                            if($result.positives -ge $config.VirusTotal.PositiveThreshold) {
                                $threatScore += $config.Scoring.url_weight
                            }
                        }
                        if($config.URLScan.Enabled) {
                            $result = Get-URLScanReport -URL $url
                            if($result.stats.malicious -gt $config.URLScan.MaliciousThreshold) {
                                $threatScore += $config.Scoring.url_weight
                            }
                            Get-URLScanScreenshot -URL $result.task.screenshotURL -OutPath $workPath"/Screenshots/"
                        }
                    }
                }

                # Score Hashes
                if($observables.hashes.Count -gt 0) {
                    ForEach($hash in $observables.hashes) {
                        if($config.VirusTotal.Enabled) {
                            $result = Get-VTHashReport -Hash $hash
                            if($result.positives -ge $config.VirusTotal.PositiveThreshold) {
                                $threatScore += $config.Scoring.hash_weight
                            }
                        }
                    }
                }

                # threatScore can't be greater than 100
                if($threatScore -gt 100) {
                    $threatScore = 100
                }


                if($config.Report.SendReport) {
                    $report = "<h1>Smells Phishy Email Report</h1>"

                    $report += "<h2>Score: $threatScore/100</h2>"
                    $report += "<h2>Message Details</h2>"
                    $report += "<h2>Observables</h2>"

                    $report += "<h3>URLs</h3>"
                    ForEach($url in ($observables.urls | Select -Uniq)) {
                        $url = Defang $url
                        $report += "<li>$url</li>"
                    }

                    $report += "<h3>Domains</h3>"
                    ForEach($domain in ($observables.domains | Select -Uniq)) {
                        $domain = Defang $domain
                        $report += "<li>$domain</li>"
                    }

                    $report += "<h3>Hashes</h3>"
                    ForEach($hash in ($observables.hashes | Select -Uniq)) {
                        $report += "<li>$hash</li>"
                    }

                    $report += "<h3>Suspicious Subject</h3>"
                    ForEach($subject in ($observables.subject_matches | Select -Uniq)) {
                        $report += "<li>$subject</li>"
                    }

                    $report += "<h3>Suspicious Phrases</h3>"
                    ForEach($phrase in ($observables.phrase_matches | Select -Uniq)) {
                        $report += "<li>$phrase</li>"
                    }

                    $report += "<h3>Suspicious Patterns</h3>"
                    ForEach($pattern in ($observables.pattern_matches | Select -Uniq)) {
                        $report += "<li>$pattern</li>"
                    }

                    $report += "<h3>Screenshots</h3>"

                    Send-Report -MailTo $config.Report.Recipient -Report $report -EmailSubject $_.Subject -Service $ExchangeService -ScreenshotsPath $workPath"/Screenshots/"
                }

                $observables

                $_.IsRead = $true
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
        [Hashtable]$Observables=$null,
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
        $observables.urls += Invoke-ExtractURLs -Data $Message.Body

        # Extract the email subject
        $observables.subjects += $Message.Subject

        # Extract the message sender
        $observables.addresses += $Message.Sender.Address

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

    } else {

        $filePath = $scriptPath+"\Analysis\"+$guid+"\Attachments\"+$Attachment.Name
        $Attachment.Load($filePath)
        $hash = (Get-FileHash $filePath -Algorithm MD5).hash
        $observables.hashes += $hash
        $observables.urls += Invoke-ExtractURLs -Data (Get-Content $filePath -Raw)

    }

    # Remove any whitelisted domains from the list
    $filtered_urls = @()
    ForEach($url in $observables.urls) {
        $found = $false
        ForEach($domain in $DomainWhitelist) {
            $filter = "*"+$domain+"*"
            if($url -like $filter) {
                $found = $true
            }
        }
        if(!$found) {
            $filtered_urls += ($url)
        }
    }
    #Write-Host $filtered_urls.Count
    $observables.urls = $filtered_urls | Select -Uniq

    # Dedup the URLs and extract the domains from the URLs
    $observables.urls = $observables.urls | Select -Uniq

    # Extract the domains from the URLs
    $observables.urls | % {
        # Add the domain if it isn't already in the list
        if($_ -like "*http*") {
            $observables.domains += (([System.URI]$_).Authority)
        }
    }

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
    $ips = $ips | Select -Uniq

    # Filter out RFC1918 addresses
    $ips = $ips | Where { (!$_.StartsWith("192.168.") -and !$_.StartsWith("172.22.16.") -and !$_.StartsWith("10.") -and $_ -ne "127.0.0.1") }

    return $ips
}

function Invoke-ExtractURLs {
    Param(
        [Parameter(Mandatory=$true)][string]$Data
    )

    # Unescape HTML
    $Data = [System.Web.HttpUtility]::HtmlDecode($Data)

    $urls = ((Select-String '\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[A-Z0-9+&@#/%=~_|$])' -AllMatches -Input $Data).Matches.Value)
    $urls = $urls | Select -Uniq
    return $urls
}

function Invoke-AnalyzeWhois {
    Param(
        [Parameter(Mandatory=$true)]$WhoisReport
    )

    process {

        $report = @{
            "new_registration" = $false;
            "recent_update" = $false;
        }

        # Get todays date so we can calculate if activity on the domain is recent
        $today = (Get-Date)

        # Extract the creation date for the domain
        $WhoisReport -match "Creation Date: ([.*\S]+Z)" | Out-Null
        if($matches) { $creationDate = $matches[1] }

        if((New-TimeSpan -Start ([datetime]$creationDate) -End $today).TotalDays -le $config.WhoisReport.NewlyRegisteredDays) {
            $report.new_registration = $true
        }

        # Extract the update date for the domain
        $WhoisReport -match "Updated Date: ([.*\S]+Z)" | Out-Null
        if($matches) { $updatedDate = $matches[1] }

        if((New-TimeSpan -Start ([datetime]$updatedDate) -End $today).TotalDays -le $config.WhoisReport.RecentUpdateDays) {
            $report.recent_update = $true
        }

        return $report
    }
}

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

function Write-Log {
    Param(
        [string]$Message,
        [switch]$Verbose
    )

    process {
        $date = '{0:yyyy-MM-dd hh:mm:ss}' -f (Get-Date)
        Write-Host "[$date] $Message"
    }
    
}

function Write-ReportLog {
    Param(
        [string]$MailFrom,
        [string]$MailSubject
    )

    $date = '{0:yyyy-MM-dd hh:mm:ss}' -f (Get-Date)
    $logPath = "\\mtlwpplogxm01\c$\Logs\phishing_report.log"
    "DATE=$date | SENDER=$MailFrom | SUBJECT=$MailSubject" | Out-File $logPath -Append
    #Get-Content $logPath
    #exit
}

Get-NewMessages -Mailbox phishing@arifleet.com 
