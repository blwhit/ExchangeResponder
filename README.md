# ExchangeResponder

PowerShell-based Blue Team tool for investigating and remediating Business Email Compromise and email-based threats in Microsoft 365 tenants.Retry

## Features

- **Email Search & Purge**: Search and delete malicious emails tenant-wide, by subject/sender/etc
- **Inbox Rule Hunting**: Find and remediate malicious inbox rules by name/action/etc
- **Mailbox Delegation**: Grant/revoke temporary mailbox access for investigation
- **Batch Processing**: Bypasses Microsoft Purview's 1,000+ mailbox search limit
- **CSV Export**: Save findings to files for review/documentation

## Installation

Clone this repository:
```powershell
git clone https://github.com/blwhit/ExchangeResponder.git
cd ExchangeResponder
```
<sub>*The script will automatically install required modules*</sub>

## Usage

Run the script:
```powershell
.\ExchangeResponder.ps1
```

The interactive menu provides access to all functions:

<img width="561" height="297" alt="image" src="https://github.com/user-attachments/assets/9de83d0f-8b9c-41e8-859c-a8b4c64b7897" />

## Requirements

- PowerShell 5.1 or later
- ExchangeOnlineManagement module v3.9.0+
- Exchange Online permissions
