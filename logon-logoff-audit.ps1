# Fixed Login/Logout Audit Script for Windows 11
# Run as Administrator for best results

param(
    [int]$Days = 7,
    [switch]$ExportToCSV,
    [string]$CSVPath = ".\LoginHistory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$ShowAll,
    [switch]$ExportToTXT,
    [string]$TXTPath = ".\LoginHistory_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Function to generate a formatted summary of events
function Get-Summary {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results
    )

    $SummaryOutput = @()

    # Group by event type
    $EventStats = $Results | Group-Object Event | Sort-Object Count -Descending
    $SummaryOutput += ""
    $SummaryOutput += "Events by Type:"
    foreach ($EventType in $EventStats) {
        $SummaryOutput += "  $($EventType.Name): $($EventType.Count)"
    }

    # Group by users (excluding system accounts)
    $UserStats = $Results | Where-Object { $_.User -notmatch '^(SYSTEM|NT AUTHORITY|WORKGROUP)' } |
                 Group-Object User | Sort-Object Count -Descending
    if ($UserStats.Count -gt 0) {
        $SummaryOutput += ""
        $SummaryOutput += "Activity by User:"
        foreach ($User in $UserStats) {
            $SummaryOutput += "  $($User.Name): $($User.Count) events"
        }
    }

    return $SummaryOutput
}

Write-Host "=== WINDOWS 11 LOGIN/LOGOUT AUDIT REPORT ===" -ForegroundColor Green
Write-Host "Checking last $Days days..." -ForegroundColor Yellow
Write-Host ""

# Calculate start date
$StartDate = (Get-Date).AddDays(-$Days)
Write-Host "Start Date: $($StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "End Date: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan

# Check admin privileges
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Running as Administrator: $IsAdmin" -ForegroundColor $(if($IsAdmin){'Green'}else{'Red'})

if (-not $IsAdmin) {
    Write-Host "WARNING: Script not running as administrator!" -ForegroundColor Red
    Write-Host "Some events may not be accessible." -ForegroundColor Yellow
}

# Event IDs for login/logout tracking
$EventIDs = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4634 = "Logoff"
    4647 = "User Initiated Logoff"
    4648 = "Logon with Explicit Credentials"
    4779 = "RDP Session Disconnected"
    4778 = "RDP Session Reconnected"
}

Write-Host ""
Write-Host "=== DIAGNOSTICS ===" -ForegroundColor Magenta

# Check Security log availability
try {
    $SecurityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    Write-Host "Security Log Available: YES" -ForegroundColor Green
    Write-Host "Log Size: $([math]::Round($SecurityLog.FileSize / 1MB, 2)) MB" -ForegroundColor White
    Write-Host "Record Count: $($SecurityLog.RecordCount)" -ForegroundColor White
} catch {
    Write-Host "Security Log Not Available: $($_.Exception.Message)" -ForegroundColor Red
    return
}

Write-Host ""
Write-Host "=== MAIN SEARCH (OPTIMIZED) ===" -ForegroundColor Green

# Array to store results
$Results = @()

try {
    # Optimized: Use a single Get-WinEvent call for all IDs
    Write-Host "Retrieving all login/logout events at once..." -ForegroundColor Cyan

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = [int[]]$EventIDs.Keys
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue

    if ($null -eq $Events) {
        # Ensure $Events is an empty array if nothing is found
        $Events = @()
    }

    # Sort all events by time
    $Events = $Events | Sort-Object TimeCreated

    Write-Host ""
    Write-Host "Found $($Events.Count) total events in specified period" -ForegroundColor Cyan

    if ($Events.Count -eq 0) {
        Write-Host ""
        Write-Host "=== NO EVENTS FOUND ===" -ForegroundColor Yellow
        Write-Host "No login/logout events found in the last $Days days."
        Write-Host ""
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Magenta

        # Programmatically check audit policies
        try {
            $LogonPolicy = (auditpol /get /subcategory:Logon | Select-String "Logon").ToString().Trim()
            Write-Host "Audit Policy for 'Logon': $LogonPolicy" -ForegroundColor $(if ($LogonPolicy -match "Success and Failure|Success") {'Green'} else {'Yellow'})

            if ($LogonPolicy -notmatch "Success and Failure|Success") {
                Write-Host " -> Logon auditing is not fully enabled. Run this command as Admin:" -ForegroundColor Yellow
                Write-Host "    auditpol /set /subcategory:Logon /success:enable /failure:enable" -ForegroundColor Gray
            }
        } catch {
            Write-Host "Could not check 'Logon' audit policy. Ensure you are running as Administrator." -ForegroundColor Red
        }

        Write-Host "Consider increasing the search time with the -Days parameter (e.g., -Days 30)." -ForegroundColor White
        return
    }

    Write-Host "Processing events..." -ForegroundColor Cyan
    $TotalEvents = $Events.Count
    $Counter = 0

    # Optimized: Use a processing pipeline to avoid slow array concatenation
    $Results = foreach ($Event in $Events) {
        $Counter++
        Write-Progress -Activity "Processing Events" -Status "Event $Counter of $TotalEvents" -PercentComplete (($Counter / $TotalEvents) * 100)

        # Initialize variables
        $Username = "N/A"
        $Domain = "N/A"
        $LogonType = "N/A"
        $SourceIP = "N/A"
        $ProcessName = "N/A"
        $WorkstationName = "N/A"

        # Optimized: Directly access event properties instead of parsing XML
        $Props = $Event.Properties

        switch ($Event.Id) {
            4624 { # Successful Logon
                if ($Props.Count -gt 18) {
                    $Username = $Props[5].Value
                    $Domain = $Props[6].Value
                    $LogonType = $Props[8].Value
                    $WorkstationName = $Props[11].Value
                    $ProcessName = $Props[17].Value
                    $SourceIP = $Props[18].Value
                }
            }
            4625 { # Failed Logon
                if ($Props.Count -gt 19) {
                    $Username = $Props[5].Value
                    $Domain = $Props[6].Value
                    $LogonType = $Props[10].Value
                    $WorkstationName = $Props[13].Value
                    $SourceIP = $Props[19].Value
                }
            }
            4634 { # Logoff
                if ($Props.Count -gt 4) {
                    $Username = $Props[1].Value
                    $Domain = $Props[2].Value
                    $LogonType = $Props[4].Value
                }
            }
            4647 { # User Initiated Logoff
                if ($Props.Count -gt 2) {
                    $Username = $Props[1].Value
                    $Domain = $Props[2].Value
                }
            }
            4648 { # Logon with Explicit Credentials
                if ($Props.Count -gt 12) {
                    $Username = $Props[5].Value # Target User
                    $Domain = $Props[6].Value
                    $ProcessName = $Props[10].Value
                    $SourceIP = $Props[12].Value
                }
            }
            4778 { # RDP Session Reconnected
                if ($Props.Count -gt 5) {
                    $Username = $Props[0].Value
                    $Domain = $Props[1].Value
                    $WorkstationName = $Props[4].Value
                    $SourceIP = $Props[5].Value
                    $LogonType = "10" # RDP is always 10
                }
            }
            4779 { # RDP Session Disconnected
                if ($Props.Count -gt 5) {
                    $Username = $Props[0].Value
                    $Domain = $Props[1].Value
                    $WorkstationName = $Props[4].Value
                    $SourceIP = $Props[5].Value
                    $LogonType = "10" # RDP is always 10
                }
            }
        }

        # Skip system/service accounts for cleaner output
        if ($Username -in @('SYSTEM', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE', '$', '')) {
            continue
        }

        # Map logon type to description
        $LogonTypeDescription = switch ($LogonType) {
            "2" { "Interactive (Console)" }
            "3" { "Network" }
            "4" { "Batch" }
            "5" { "Service" }
            "7" { "Unlock" }
            "8" { "NetworkCleartext" }
            "9" { "NewCredentials" }
            "10" { "RemoteInteractive (RDP)" }
            "11" { "CachedInteractive" }
            default { "Type $LogonType" }
        }

        # Clean up source information
        $SourceInfo = "Local"
        if ($SourceIP -and $SourceIP -ne "-" -and $SourceIP -ne "::1" -and $SourceIP -ne "127.0.0.1" -and $SourceIP -ne "::ffff:127.0.0.1") {
            $SourceInfo = $SourceIP
        } elseif ($WorkstationName -and $WorkstationName -ne "-" -and $WorkstationName -ne $env:COMPUTERNAME) {
            $SourceInfo = $WorkstationName
        }

        # Create and output the result object, which will be collected by $Results
        [PSCustomObject]@{
            Date = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Event = $EventIDs[$Event.Id]
            User = if ($Domain -and $Domain -ne "-") { "$Domain\$Username" } else { $Username }
            "Logon Type" = $LogonTypeDescription
            Source = $SourceInfo
            Process = if ($ProcessName) { Split-Path $ProcessName -Leaf } else { "N/A" }
            "Event ID" = $Event.Id
            Computer = $Event.MachineName
        }
    }
    # Hide the progress bar after completion
    Write-Progress -Activity "Processing Events" -Completed

    # Display results
    if ($Results.Count -gt 0) {
        Write-Host ""
        Write-Host "=== FOUND LOGIN/LOGOUT EVENTS ===" -ForegroundColor Green

        # Show events based on ShowAll parameter
        if ($ShowAll) {
            Write-Host "Showing all $($Results.Count) events:" -ForegroundColor Cyan
            $Results | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "Showing first 20 events (use -ShowAll to see all):" -ForegroundColor Cyan
            $Results | Select-Object -First 20 | Format-Table -AutoSize -Wrap

            if ($Results.Count -gt 20) {
                Write-Host "... showing first 20 of $($Results.Count) total events (use -ShowAll parameter to see all)" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "=== SUMMARY ===" -ForegroundColor Green
        Write-Host "Total Events: $($Results.Count)" -ForegroundColor White
        Write-Host "Period: $(Get-Date $StartDate -Format 'yyyy-MM-dd HH:mm') - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White

        # Use the reusable function to get summary
        $SummaryLines = Get-Summary -Results $Results
        foreach ($Line in $SummaryLines) {
            Write-Host $Line -ForegroundColor Cyan
        }

        # Export to files if requested
        if ($ExportToCSV) {
            $Results | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8
            Write-Host ""
            Write-Host "Results exported to CSV: $CSVPath" -ForegroundColor Green
        }

        if ($ExportToTXT) {
            # Create formatted text output
            $TextOutput = @()
            $TextOutput += "=== WINDOWS 11 LOGIN/LOGOUT AUDIT REPORT ==="
            $TextOutput += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $TextOutput += "Period: $(Get-Date $StartDate -Format 'yyyy-MM-dd HH:mm') - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            $TextOutput += "Total Events: $($Results.Count)"
            $TextOutput += ""
            $TextOutput += "=== LOGIN/LOGOUT EVENTS ==="

            foreach ($Result in $Results) {
                $TextOutput += "Date/Time: $($Result.Date)"
                $TextOutput += "Event: $($Result.Event) (ID: $($Result.'Event ID'))"
                $TextOutput += "User: $($Result.User)"
                $TextOutput += "Logon Type: $($Result.'Logon Type')"
                $TextOutput += "Source: $($Result.Source)"
                $TextOutput += "Process: $($Result.Process)"
                $TextOutput += "Computer: $($Result.Computer)"
                $TextOutput += "----------------------------------------"
            }

            $TextOutput += ""
            $TextOutput += "=== SUMMARY ==="

            # Use the reusable function to get summary for the text file
            $SummaryLines = Get-Summary -Results $Results
            $TextOutput += $SummaryLines

            # Write to file with UTF8 encoding
            $TextOutput | Out-File -FilePath $TXTPath -Encoding UTF8
            Write-Host ""
            Write-Host "Results exported to TXT: $TXTPath" -ForegroundColor Green
        }

    } else {
        Write-Host "No user login/logout events found in specified period." -ForegroundColor Yellow
        Write-Host "(System account events were filtered out)" -ForegroundColor Gray
    }

} catch {
    Write-Host "Error retrieving events: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error details:" -ForegroundColor Yellow
    Write-Host $_.Exception.ToString() -ForegroundColor Gray
}