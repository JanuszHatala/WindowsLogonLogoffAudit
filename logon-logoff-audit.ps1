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
Write-Host "=== MAIN SEARCH (FIXED) ===" -ForegroundColor Green

# Array to store results
$Results = @()

try {
    Write-Host "Retrieving login/logout events with improved filtering..." -ForegroundColor Cyan
    
    # FIXED: Use StartTime in FilterHashtable instead of filtering afterwards
    # This is more efficient and reliable
    $Events = @()
    
    foreach ($EventID in $EventIDs.Keys) {
        try {
            Write-Host "Searching for Event ID $EventID ($($EventIDs[$EventID]))..." -ForegroundColor Gray
            
            $EventsForID = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = $EventID
                StartTime = $StartDate
            } -ErrorAction SilentlyContinue
            
            if ($EventsForID) {
                Write-Host "  Found $($EventsForID.Count) events for ID $EventID" -ForegroundColor Green
                $Events += $EventsForID
            } else {
                Write-Host "  No events found for ID $EventID" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Error searching for ID $EventID : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Sort all events by time
    $Events = $Events | Sort-Object TimeCreated -Descending
    
    Write-Host ""
    Write-Host "Found $($Events.Count) total events in specified period" -ForegroundColor Cyan
    
    if ($Events.Count -eq 0) {
        Write-Host ""
        Write-Host "=== EXTENDED SEARCH ===" -ForegroundColor Yellow
        
        # Try a broader search to see if there are ANY events
        Write-Host "Trying search without time restriction..." -ForegroundColor Cyan
        
        $AllEvents = @()
        foreach ($EventID in $EventIDs.Keys) {
            try {
                $EventsForID = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = $EventID
                } -MaxEvents 10 -ErrorAction SilentlyContinue
                
                if ($EventsForID) {
                    $AllEvents += $EventsForID
                }
            } catch {
                # Ignore errors for this test
            }
        }
        
        if ($AllEvents.Count -gt 0) {
            $AllEvents = $AllEvents | Sort-Object TimeCreated -Descending
            Write-Host "Found $($AllEvents.Count) login events TOTAL (any time)" -ForegroundColor Green
            Write-Host "Latest event: $($AllEvents[0].TimeCreated)" -ForegroundColor White
            Write-Host "Oldest event: $($AllEvents[-1].TimeCreated)" -ForegroundColor White
            
            # Check if any events are within our time range
            $RecentEvents = $AllEvents | Where-Object { $_.TimeCreated -ge $StartDate }
            if ($RecentEvents.Count -eq 0) {
                Write-Host ""
                Write-Host "DIAGNOSIS: Events exist but none in the last $Days days" -ForegroundColor Yellow
                Write-Host "Try increasing the -Days parameter (e.g., -Days 30)" -ForegroundColor White
            }
        } else {
            Write-Host "Found NO login events in Security log!" -ForegroundColor Red
            Write-Host ""
            Write-Host "TROUBLESHOOTING STEPS:" -ForegroundColor Yellow
            Write-Host "1. Check if audit policy is enabled:" -ForegroundColor White
            Write-Host "   auditpol /get /subcategory:Logon" -ForegroundColor Gray
            Write-Host "2. Enable auditing if needed:" -ForegroundColor White
            Write-Host "   auditpol /set /subcategory:Logon /success:enable /failure:enable" -ForegroundColor Gray
            Write-Host "3. Check if someone cleared the event log recently" -ForegroundColor White
        }
        return
    }

    Write-Host "Processing events..." -ForegroundColor Cyan

    foreach ($Event in $Events) {
        # Convert XML to object for detailed parsing
        $EventXML = [xml]$Event.ToXml()
        
        # Initialize variables
        $Username = "N/A"
        $Domain = "N/A"
        $LogonType = "N/A"
        $SourceIP = "N/A"
        $ProcessName = "N/A"
        $WorkstationName = "N/A"
        
        # Get event details from EventData
        $EventData = $EventXML.Event.EventData.Data
        
        foreach ($Data in $EventData) {
            switch ($Data.Name) {
                "TargetUserName" { $Username = $Data.'#text' }
                "TargetDomainName" { $Domain = $Data.'#text' }
                "LogonType" { $LogonType = $Data.'#text' }
                "IpAddress" { $SourceIP = $Data.'#text' }
                "ProcessName" { $ProcessName = $Data.'#text' }
                "WorkstationName" { $WorkstationName = $Data.'#text' }
                # Fallback to Subject fields for logoff events
                "SubjectUserName" { if ($Username -eq "N/A" -or [string]::IsNullOrEmpty($Username)) { $Username = $Data.'#text' } }
                "SubjectDomainName" { if ($Domain -eq "N/A" -or [string]::IsNullOrEmpty($Domain)) { $Domain = $Data.'#text' } }
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

        # Create result object
        $Result = [PSCustomObject]@{
            Date = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Event = $EventIDs[$Event.Id]
            User = if ($Domain -and $Domain -ne "-") { "$Domain\$Username" } else { $Username }
            "Logon Type" = $LogonTypeDescription
            Source = $SourceInfo
            Process = if ($ProcessName) { Split-Path $ProcessName -Leaf } else { "N/A" }
            "Event ID" = $Event.Id
            Computer = $Event.MachineName
        }
        
        $Results += $Result
    }

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
        
        # Group by event type
        $EventStats = $Results | Group-Object Event | Sort-Object Count -Descending
        Write-Host ""
        Write-Host "Events by Type:" -ForegroundColor Cyan
        foreach ($EventType in $EventStats) {
            Write-Host "  $($EventType.Name): $($EventType.Count)" -ForegroundColor White
        }
        
        # Group by users (excluding system accounts)
        $UserStats = $Results | Where-Object { $_.User -notmatch '^(SYSTEM|NT AUTHORITY|WORKGROUP)' } | 
                     Group-Object User | Sort-Object Count -Descending
        if ($UserStats.Count -gt 0) {
            Write-Host ""
            Write-Host "Activity by User:" -ForegroundColor Cyan
            foreach ($User in $UserStats) {
                Write-Host "  $($User.Name): $($User.Count) events" -ForegroundColor White
            }
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
            
            # Add event type summary
            $EventStats = $Results | Group-Object Event | Sort-Object Count -Descending
            $TextOutput += ""
            $TextOutput += "Events by Type:"
            foreach ($EventType in $EventStats) {
                $TextOutput += "  $($EventType.Name): $($EventType.Count)"
            }
            
            # Add user summary
            $UserStats = $Results | Where-Object { $_.User -notmatch '^(SYSTEM|NT AUTHORITY|WORKGROUP)' } | 
                         Group-Object User | Sort-Object Count -Descending
            if ($UserStats.Count -gt 0) {
                $TextOutput += ""
                $TextOutput += "Activity by User:"
                foreach ($User in $UserStats) {
                    $TextOutput += "  $($User.Name): $($User.Count) events"
                }
            }
            
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