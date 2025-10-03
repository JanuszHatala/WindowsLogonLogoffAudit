# Windows Login/Logout Audit Script

A PowerShell script for auditing user login and logout events on Windows 11 systems. Extracts detailed information from Windows Security logs and provides comprehensive reporting with export capabilities.

## Features

- **Comprehensive Event Tracking**: Monitors login, logout, failed logon attempts, RDP sessions, and more.
- **Flexible Time Range**: Configurable date range (default: last 7 days).
- **Multiple Export Formats**: Export to CSV or formatted TXT files.
- **Detailed Diagnostics**: Built-in troubleshooting and audit policy checking.
- **Clean Output**: Filters out system accounts for focused user activity reports. The following accounts are filtered: `SYSTEM`, `ANONYMOUS LOGON`, `LOCAL SERVICE`, `NETWORK SERVICE`, and accounts ending in `$`.
- **Admin Privilege Detection**: Warns if not running with administrator rights.
- **Detailed Summary**: Provides a summary of events by type and user activity.
- **Chronological Sorting**: Displays events from oldest to newest to make them easier to follow.

## Requirements

- Windows 11 (may work on Windows 10)
- PowerShell 5.1 or later
- Administrator privileges (recommended for full access to Security logs)

## Usage

### Basic Usage
```powershell
# Run with default settings (last 7 days)
powershell -ExecutionPolicy Bypass -File ".\logon-logoff-audit.ps1"
```

### Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-Days` | Integer | Number of days to look back | 7 |
| `-ShowAll` | Switch | Display all events (not just first 20) | False |
| `-ExportToCSV` | Switch | Export results to CSV file | False |
| `-CSVPath` | String | Custom CSV file path | `.\LoginHistory_YYYYMMDD_HHMMSS.csv` |
| `-ExportToTXT` | Switch | Export results to formatted TXT file | False |
| `-TXTPath` | String | Custom TXT file path | `.\LoginHistory_YYYYMMDD_HHMMSS.txt` |

### Examples

```powershell
# Check last 30 days and show all events
powershell -ExecutionPolicy Bypass -File ".\logon-logoff-audit.ps1" -Days 30 -ShowAll

# Export to both CSV and TXT files
powershell -ExecutionPolicy Bypass -File ".\logon-logoff-audit.ps1" -ExportToCSV -ExportToTXT

# Custom time range with specific export paths
powershell -ExecutionPolicy Bypass -File ".\logon-logoff-audit.ps1" -Days 14 -ExportToTXT -TXTPath "C:\Reports\LoginAudit.txt"

# Complete audit with all options
powershell -ExecutionPolicy Bypass -File ".\logon-logoff-audit.ps1" -Days 30 -ShowAll -ExportToCSV -ExportToTXT
```

## Event Types Monitored

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4647 | User Initiated Logoff |
| 4648 | Logon with Explicit Credentials |
| 4778 | RDP Session Reconnected |
| 4779 | RDP Session Disconnected |

## Output Information

The script provides the following details for each event, sorted from **oldest to newest**:
- **Date/Time**: When the event occurred
- **Event Type**: Type of login/logout event
- **User**: Username and domain
- **Logon Type**: Method of authentication (Console, RDP, Network, etc.)
- **Source**: Source IP address or "Local" for console logins
- **Process**: Process that initiated the logon
- **Event ID**: The Windows Event ID for the record
- **Computer**: Machine name where event occurred

## Output Summary
After displaying the events, the script provides a summary that includes:
- **Total Events**: The total number of events found.
- **Events by Type**: A breakdown of event counts by type (e.g., Successful Logon, Logoff).
- **Activity by User**: A count of events per user.

## Troubleshooting

The script includes a **Diagnostics** section to help with troubleshooting. If no events are found, it will automatically:
1.  **Check for Security Log Access**: Verifies that the script can access the Security event log.
2.  **Check Audit Policies**: Checks if the necessary audit policies for "Logon" and "Logoff" are enabled. If not, it provides the commands to enable them:
   ```cmd
   auditpol /set /subcategory:Logon /success:enable /failure:enable
   auditpol /set /subcategory:Logoff /success:enable
   ```

### Common Issues
- **Not running as Administrator**: The script may not be able to read the Security log.
- **Audit policies disabled**: Windows may not be logging the events.
- **Event log cleared recently**: There may be no events to find in the specified time range.
- **Time range too narrow**: Try increasing the number of days with the `-Days` parameter.

## Security Considerations

- Run with Administrator privileges for complete access to Security logs
- The script only reads event logs and does not modify system settings
- Exported files may contain sensitive information - handle appropriately
- Consider data retention policies when storing audit reports

## License

This project is open source. Feel free to modify and distribute as needed.

## Contributing

Please ensure any modifications maintain the script's diagnostic capabilities and error handling.