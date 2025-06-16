# Windows Login/Logout Audit Script

A PowerShell script for auditing user login and logout events on Windows 11 systems. Extracts detailed information from Windows Security logs and provides comprehensive reporting with export capabilities.

## Features

- **Comprehensive Event Tracking**: Monitors login, logout, failed logon attempts, RDP sessions, and more
- **Flexible Time Range**: Configurable date range (default: last 7 days)
- **Multiple Export Formats**: Export to CSV or formatted TXT files
- **Detailed Diagnostics**: Built-in troubleshooting and audit policy checking
- **Clean Output**: Filters out system accounts for focused user activity reports
- **Admin Privilege Detection**: Warns if not running with administrator rights

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

The script provides the following details for each event:
- **Date/Time**: When the event occurred
- **Event Type**: Type of login/logout event
- **User**: Username and domain
- **Logon Type**: Method of authentication (Console, RDP, Network, etc.)
- **Source**: Source IP address or "Local" for console logins
- **Process**: Process that initiated the logon
- **Computer**: Machine name where event occurred

## Troubleshooting

If no events are found, the script provides diagnostic information:

1. **Enable Audit Policies** (run as Administrator):
   ```cmd
   auditpol /set /subcategory:Logon /success:enable /failure:enable
   auditpol /set /subcategory:Logoff /success:enable
   ```

2. **Check Current Audit Settings**:
   ```cmd
   auditpol /get /subcategory:Logon
   ```

3. **Common Issues**:
   - Not running as Administrator
   - Audit policies disabled
   - Event log cleared recently
   - Time range too narrow

## Security Considerations

- Run with Administrator privileges for complete access to Security logs
- The script only reads event logs and does not modify system settings
- Exported files may contain sensitive information - handle appropriately
- Consider data retention policies when storing audit reports

## License

This project is open source. Feel free to modify and distribute as needed.

## Contributing

Please ensure any modifications maintain the script's diagnostic capabilities and error handling.
