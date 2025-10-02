<#
.SYNOPSIS
    Exchange Online DFIR Script
    
.DESCRIPTION
    Comprehensive tool for:
    1. Searching and purging malicious emails tenant-wide
    2. Hunting malicious inbox rules across all mailboxes
    3. Delegating and removing mailbox access for investigations
    4. Managing compliance searches and actions
    
.NOTES
    Name:         ExchangeResponder.ps1
    Author:       Blake White
    Requirements: ExchangeOnlineManagement module v3.9.0+
#>

# Configuration
$Script:MailboxCache = $null
$Script:MailboxCacheTime = $null
$Script:RequiredModuleVersion = '3.9.0'

#region Module Management
function Install-RequiredModules {
    $moduleName = 'ExchangeOnlineManagement'
    
    try {
        $installedModule = Get-Module -ListAvailable -Name $moduleName | 
        Where-Object { $_.Version -ge [Version]$Script:RequiredModuleVersion } | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
        
        if ($installedModule) {
            Write-Log "Module '$moduleName' version $($installedModule.Version) is installed" -Level INFO
            return $true
        }
        
        Write-Log "Module '$moduleName' version $Script:RequiredModuleVersion or higher not found" -Level WARNING
        $install = Read-Host "Install/update to version $Script:RequiredModuleVersion? (y/n)"
        
        if ($install -ne 'y') {
            Write-Log "Module installation declined. Exiting." -Level ERROR
            return $false
        }
        
        Write-Log "Installing $moduleName version $Script:RequiredModuleVersion..." -Level INFO
        Install-Module -Name $moduleName -RequiredVersion $Script:RequiredModuleVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Log "Module installed successfully" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Failed to install module: $_" -Level ERROR
        
        try {
            $existingModule = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
            if ($existingModule) {
                Write-Log "Found existing version $($existingModule.Version). Attempting to use it..." -Level WARNING
                return $true
            }
        }
        catch {
            Write-Log "No usable module version found" -Level ERROR
        }
        
        return $false
    }
}
#endregion

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'INFO' { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Show-Banner {
    $banner = @"

======================================
      [   ExchangeResponder   ]
======================================
                                                           
  [1] Search and Purge Emails                            
  [2] Hunt Malicious Inbox Rules
  [3] Manage Mailbox Delegations
  [4] Manage Compliance Searches
  [5] Exit            

=======================================

"@
    Write-Host $banner -ForegroundColor Cyan
}
#endregion

#region Connection Management
function Connect-ExchangeServices {
    Write-Log "Connecting to Exchange Online..." -Level INFO
    
    try {
        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingConnection) {
            Write-Log "Already connected to Exchange Online" -Level SUCCESS
            return $true
        }
        
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Connected to Exchange Online" -Level SUCCESS
        
        Connect-IPPSSession -WarningAction SilentlyContinue -ErrorAction Stop -ShowBanner:$false
        Write-Log "Connected to Security & Compliance Center" -Level SUCCESS
        
        return $true
    }
    catch {
        Write-Log "Connection failed: $_" -Level ERROR
        return $false
    }
}

function Disconnect-ExchangeServices {
    Write-Log "Disconnecting from Exchange Online..." -Level INFO
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Disconnected successfully" -Level SUCCESS
    }
    catch {
        # Silent disconnect errors
    }
}
#endregion

#region Mailbox Cache Functions
function Get-CachedMailboxes {
    param([switch]$ForceRefresh)
    
    $cacheExpiration = 600
    
    if (-not $ForceRefresh -and $Script:MailboxCache -and $Script:MailboxCacheTime) {
        $timeSinceCache = (Get-Date) - $Script:MailboxCacheTime
        if ($timeSinceCache.TotalSeconds -lt $cacheExpiration) {
            Write-Log "Using cached mailbox data ($($Script:MailboxCache.Count) mailboxes)" -Level INFO
            return $Script:MailboxCache
        }
    }
    
    Write-Log "Retrieving mailbox list..." -Level INFO
    try {
        $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | 
        Where-Object { $_.RecipientTypeDetails -ne 'DiscoveryMailbox' } |
        Select-Object UserPrincipalName, DisplayName, RecipientTypeDetails
        
        $Script:MailboxCache = $mailboxes
        $Script:MailboxCacheTime = Get-Date
        
        Write-Log "Retrieved $($mailboxes.Count) mailboxes" -Level SUCCESS
        return $mailboxes
    }
    catch {
        Write-Log "Error retrieving mailboxes: $_" -Level ERROR
        return $null
    }
}
#endregion

#region Export Functions
function Export-ToCSV {
    param(
        [Parameter(Mandatory = $true)]
        $Data,
        [string]$DefaultFileName
    )
    
    Write-Host ""
    $response = Read-Host "Export to CSV? (y/n or Enter to skip)"
    
    if ($response -eq 'y') {
        $defaultPath = ".\$DefaultFileName.csv"
        Write-Host "`nDefault: $defaultPath" -ForegroundColor Cyan
        $customPath = Read-Host "Custom path (or Enter for default)"
        
        $exportPath = if ($customPath) { $customPath } else { $defaultPath }
        
        try {
            $exportDir = Split-Path -Parent $exportPath
            if ($exportDir -and -not (Test-Path $exportDir)) {
                New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
            }
            
            $Data | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            Write-Log "Exported to: $exportPath" -Level SUCCESS
        }
        catch {
            Write-Log "Export failed: $_" -Level ERROR
        }
    }
}
#endregion

#region Mailbox Delegation
function Start-MailboxDelegation {
    Write-Host "`n=== Delegate Mailbox Access ===" -ForegroundColor Cyan
    Write-Host "Grant temporary access for investigation`n"
    
    $targetMailbox = Read-Host "Target mailbox (user@domain.com)"
    if (-not $targetMailbox) {
        Write-Log "No target specified" -Level WARNING
        return
    }
    
    $delegateUser = Read-Host "Delegate to (admin@domain.com)"
    if (-not $delegateUser) {
        Write-Log "No delegate specified" -Level WARNING
        return
    }
    
    Write-Host "`nGranting FullAccess to:" -ForegroundColor Yellow
    Write-Host "  Target: $targetMailbox"
    Write-Host "  Delegate: $delegateUser"
    Write-Host "  AutoMapping: Disabled`n"
    
    $confirm = Read-Host "Proceed? (y/n)"
    if ($confirm -ne 'y') {
        Write-Log "Cancelled" -Level INFO
        return
    }
    
    try {
        Add-MailboxPermission -Identity $targetMailbox -User $delegateUser -AccessRights FullAccess -AutoMapping:$false -ErrorAction Stop | Out-Null
        
        Write-Log "Access granted successfully" -Level SUCCESS
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "DELEGATION COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Target: $targetMailbox"
        Write-Host "Delegate: $delegateUser"
        Write-Host "Access Rights: FullAccess"
        Write-Host "AutoMapping: Disabled"
        Write-Host "`nAccess URL (use incognito):" -ForegroundColor Cyan
        Write-Host "https://outlook.office.com/mail/$targetMailbox/" -ForegroundColor Yellow
        Write-Host "`nREMINDER: Remove access after investigation" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Green
        
        $data = [PSCustomObject]@{
            Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            TargetMailbox = $targetMailbox
            DelegateUser  = $delegateUser
            AccessRights  = 'FullAccess'
            AutoMapping   = $false
            AccessURL     = "https://outlook.office.com/mail/$targetMailbox/"
        }
        
        Export-ToCSV -Data $data -DefaultFileName "MailboxDelegation_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    catch {
        Write-Log "Failed to grant access: $_" -Level ERROR
    }
}

function Remove-MailboxDelegation {
    Write-Host "`n=== Remove Mailbox Delegation ===" -ForegroundColor Cyan
    Write-Host "Remove delegated access from mailbox`n"
    
    $targetMailbox = Read-Host "Target mailbox (user@domain.com)"
    if (-not $targetMailbox) {
        Write-Log "No target specified" -Level WARNING
        return
    }
    
    try {
        $permissions = Get-MailboxPermission -Identity $targetMailbox -ErrorAction Stop | 
        Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and $_.IsInherited -eq $false }
        
        if ($permissions.Count -eq 0) {
            Write-Log "No delegated permissions found on $targetMailbox" -Level INFO
            return
        }
        
        Write-Host "Current delegations on $targetMailbox`:" -ForegroundColor Yellow
        $index = 1
        foreach ($perm in $permissions) {
            Write-Host "  [$index] User: $($perm.User) | Rights: $($perm.AccessRights -join ', ')"
            $index++
        }
        
        Write-Host ""
        $choice = Read-Host "Enter number to remove (or 'all' for all delegations)"
        
        if ($choice -eq 'all') {
            $confirm = Read-Host "Remove ALL delegations? Type 'REMOVE-ALL' to confirm"
            if ($confirm -eq 'REMOVE-ALL') {
                foreach ($perm in $permissions) {
                    try {
                        Remove-MailboxPermission -Identity $targetMailbox -User $perm.User -AccessRights $perm.AccessRights -Confirm:$false -ErrorAction Stop
                        Write-Log "Removed $($perm.User) from $targetMailbox" -Level SUCCESS
                    }
                    catch {
                        Write-Log "Failed to remove $($perm.User): $_" -Level ERROR
                    }
                }
            }
        }
        elseif ($choice -match '^\d+$') {
            $selectedIndex = [int]$choice - 1
            if ($selectedIndex -ge 0 -and $selectedIndex -lt $permissions.Count) {
                $selectedPerm = $permissions[$selectedIndex]
                $confirm = Read-Host "Remove $($selectedPerm.User)? (y/n)"
                if ($confirm -eq 'y') {
                    Remove-MailboxPermission -Identity $targetMailbox -User $selectedPerm.User -AccessRights $selectedPerm.AccessRights -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed $($selectedPerm.User) from $targetMailbox" -Level SUCCESS
                }
            }
            else {
                Write-Log "Invalid selection" -Level WARNING
            }
        }
    }
    catch {
        Write-Log "Error managing delegations: $_" -Level ERROR
    }
}

function Manage-MailboxDelegations {
    while ($true) {
        Write-Host "`n=== Mailbox Delegation Management ===" -ForegroundColor Cyan
        Write-Host "  1. Add delegation"
        Write-Host "  2. Remove delegation"
        Write-Host "  3. View delegations for mailbox"
        Write-Host "  4. Back to main menu"
        
        $choice = Read-Host "`nSelect (1-4)"
        
        switch ($choice) {
            '1' { 
                Start-MailboxDelegation
                Read-Host "`nPress Enter to continue"
            }
            '2' { 
                Remove-MailboxDelegation
                Read-Host "`nPress Enter to continue"
            }
            '3' {
                $mailbox = Read-Host "`nEnter mailbox"
                if ($mailbox) {
                    try {
                        $perms = Get-MailboxPermission -Identity $mailbox -ErrorAction Stop | 
                        Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and $_.IsInherited -eq $false }
                        
                        if ($perms.Count -eq 0) {
                            Write-Log "No delegations found" -Level INFO
                        }
                        else {
                            Write-Host "`nDelegations for $mailbox`:" -ForegroundColor Yellow
                            foreach ($perm in $perms) {
                                Write-Host "  User: $($perm.User)"
                                Write-Host "  Rights: $($perm.AccessRights -join ', ')"
                                Write-Host "  Deny: $($perm.Deny)"
                                Write-Host ""
                            }
                        }
                    }
                    catch {
                        Write-Log "Error retrieving delegations: $_" -Level ERROR
                    }
                }
                Read-Host "Press Enter to continue"
            }
            '4' { return }
            default { Write-Host "Invalid selection" -ForegroundColor Red }
        }
    }
}
#endregion

#region Inbox Rules
function Get-SuspiciousInboxRules {
    param(
        [string]$RuleNamePattern,
        [string]$ActionType,
        [switch]$EnabledOnly,
        [string]$DescriptionPattern,
        [string]$MailboxFilter
    )
    
    Write-Log "Starting inbox rule hunt..." -Level INFO
    
    try {
        $allMailboxes = if ($MailboxFilter) {
            if ($MailboxFilter -like '*`**') {
                Get-CachedMailboxes | Where-Object { 
                    $_.UserPrincipalName -like $MailboxFilter -or $_.DisplayName -like $MailboxFilter 
                }
            }
            else {
                Get-Mailbox -Identity $MailboxFilter -ErrorAction Stop
            }
        }
        else {
            Get-CachedMailboxes
        }
    }
    catch {
        Write-Log "Error retrieving mailboxes: $_" -Level ERROR
        return $null
    }
    
    if (-not $allMailboxes) {
        Write-Log "No mailboxes found" -Level WARNING
        return $null
    }
    
    $totalMailboxes = @($allMailboxes).Count
    Write-Log "Scanning $totalMailboxes mailboxes" -Level INFO
    
    $suspiciousRules = @()
    $current = 0
    
    foreach ($mailbox in $allMailboxes) {
        $current++
        Write-Progress -Activity "Scanning for suspicious rules" -Status "Processing $($mailbox.UserPrincipalName) ($current/$totalMailboxes)" -PercentComplete (($current / $totalMailboxes) * 100)
        
        try {
            $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop
            
            foreach ($rule in $rules) {
                if ($EnabledOnly -and -not $rule.Enabled) { continue }
                
                $isSuspicious = $false
                $reasons = @()
                
                if ($RuleNamePattern -and $rule.Name -like $RuleNamePattern) {
                    $isSuspicious = $true
                    $reasons += "Name matches: $RuleNamePattern"
                }
                
                if ($DescriptionPattern -and $rule.Description -like $DescriptionPattern) {
                    $isSuspicious = $true
                    $reasons += "Description matches: $DescriptionPattern"
                }
                
                if ($ActionType) {
                    $matchesAction = switch ($ActionType) {
                        'ForwardTo' { $rule.ForwardTo -or $rule.ForwardAsAttachmentTo }
                        'RedirectTo' { $rule.RedirectTo }
                        'DeleteMessage' { $rule.DeleteMessage }
                        'MoveToFolder' { $rule.MoveToFolder }
                        'MarkAsRead' { $rule.MarkAsRead }
                        default { $false }
                    }
                    
                    if ($matchesAction) {
                        $isSuspicious = $true
                        $reasons += "Action: $ActionType"
                    }
                }
                
                if (-not $RuleNamePattern -and -not $ActionType -and -not $DescriptionPattern) {
                    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                        $isSuspicious = $true
                        $reasons += "Forwarding/Redirect rule"
                    }
                    if ($rule.DeleteMessage) {
                        $isSuspicious = $true
                        $reasons += "Auto-delete rule"
                    }
                }
                
                if ($isSuspicious) {
                    $suspiciousRules += [PSCustomObject]@{
                        Mailbox               = $mailbox.UserPrincipalName
                        DisplayName           = $mailbox.DisplayName
                        RuleName              = $rule.Name
                        RuleIdentity          = $rule.Identity
                        Enabled               = $rule.Enabled
                        Priority              = $rule.Priority
                        Description           = $rule.Description
                        ForwardTo             = ($rule.ForwardTo -join '; ')
                        ForwardAsAttachmentTo = ($rule.ForwardAsAttachmentTo -join '; ')
                        RedirectTo            = ($rule.RedirectTo -join '; ')
                        DeleteMessage         = $rule.DeleteMessage
                        SoftDeleteMessage     = $rule.SoftDeleteMessage
                        MoveToFolder          = $rule.MoveToFolder
                        CopyToFolder          = $rule.CopyToFolder
                        MarkAsRead            = $rule.MarkAsRead
                        MarkImportance        = $rule.MarkImportance
                        ApplyCategory         = ($rule.ApplyCategory -join '; ')
                        From                  = ($rule.From -join '; ')
                        SentTo                = ($rule.SentTo -join '; ')
                        SubjectContainsWords  = ($rule.SubjectContainsWords -join '; ')
                        SubjectOrBodyContains = ($rule.SubjectOrBodyContainsWords -join '; ')
                        BodyContainsWords     = ($rule.BodyContainsWords -join '; ')
                        ReceivedAfterDate     = $rule.ReceivedAfterDate
                        ReceivedBeforeDate    = $rule.ReceivedBeforeDate
                        HasAttachment         = $rule.HasAttachment
                        MessageTypeMatches    = $rule.MessageTypeMatches
                        Reasons               = ($reasons -join ' | ')
                    }
                }
            }
        }
        catch {
            Write-Log "Error scanning $($mailbox.UserPrincipalName): $_" -Level WARNING
            continue
        }
    }
    
    Write-Progress -Activity "Scanning mailboxes" -Completed
    
    if ($suspiciousRules.Count -eq 0) {
        Write-Log "No suspicious rules found" -Level INFO
        return $null
    }
    
    Write-Log "Found $($suspiciousRules.Count) suspicious rules" -Level WARNING
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SUSPICIOUS RULES: $($suspiciousRules.Count)" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    
    foreach ($rule in $suspiciousRules) {
        Write-Host "`n----------------------------------------" -ForegroundColor Gray
        Write-Host "MAILBOX: $($rule.Mailbox)" -ForegroundColor White
        Write-Host "Display Name: $($rule.DisplayName)" -ForegroundColor Gray
        Write-Host "`nRULE NAME: $($rule.RuleName)" -ForegroundColor Yellow
        Write-Host "Enabled: $($rule.Enabled)" -ForegroundColor $(if ($rule.Enabled) { 'Red' } else { 'Green' })
        Write-Host "Priority: $($rule.Priority)"
        
        if ($rule.Description) {
            Write-Host "`nDescription: $($rule.Description)" -ForegroundColor Gray
        }
        
        Write-Host "`nACTIONS:" -ForegroundColor Cyan
        if ($rule.ForwardTo) { 
            Write-Host "  > FORWARDS TO: $($rule.ForwardTo)" -ForegroundColor Red 
        }
        if ($rule.ForwardAsAttachmentTo) { 
            Write-Host "  > FORWARDS AS ATTACHMENT TO: $($rule.ForwardAsAttachmentTo)" -ForegroundColor Red 
        }
        if ($rule.RedirectTo) { 
            Write-Host "  > REDIRECTS TO: $($rule.RedirectTo)" -ForegroundColor Red 
        }
        if ($rule.DeleteMessage) { 
            Write-Host "  > DELETES MESSAGES" -ForegroundColor Red 
        }
        if ($rule.SoftDeleteMessage) { 
            Write-Host "  > SOFT DELETES MESSAGES" -ForegroundColor Red 
        }
        if ($rule.MoveToFolder) { 
            Write-Host "  > Moves to folder: $($rule.MoveToFolder)" -ForegroundColor Yellow 
        }
        if ($rule.CopyToFolder) { 
            Write-Host "  > Copies to folder: $($rule.CopyToFolder)" -ForegroundColor Yellow 
        }
        if ($rule.MarkAsRead) { 
            Write-Host "  > Marks as read" -ForegroundColor Yellow 
        }
        if ($rule.MarkImportance) { 
            Write-Host "  > Marks importance: $($rule.MarkImportance)" -ForegroundColor Yellow 
        }
        if ($rule.ApplyCategory) { 
            Write-Host "  > Applies category: $($rule.ApplyCategory)" -ForegroundColor Yellow 
        }
        
        Write-Host "`nCONDITIONS:" -ForegroundColor Cyan
        if ($rule.From) { 
            Write-Host "  From: $($rule.From)" -ForegroundColor Gray 
        }
        if ($rule.SentTo) { 
            Write-Host "  Sent To: $($rule.SentTo)" -ForegroundColor Gray 
        }
        if ($rule.SubjectContainsWords) { 
            Write-Host "  Subject contains: $($rule.SubjectContainsWords)" -ForegroundColor Gray 
        }
        if ($rule.SubjectOrBodyContains) { 
            Write-Host "  Subject/Body contains: $($rule.SubjectOrBodyContains)" -ForegroundColor Gray 
        }
        if ($rule.BodyContainsWords) { 
            Write-Host "  Body contains: $($rule.BodyContainsWords)" -ForegroundColor Gray 
        }
        if ($rule.HasAttachment) { 
            Write-Host "  Has attachment: Yes" -ForegroundColor Gray 
        }
        if ($rule.ReceivedAfterDate) { 
            Write-Host "  Received after: $($rule.ReceivedAfterDate)" -ForegroundColor Gray 
        }
        if ($rule.ReceivedBeforeDate) { 
            Write-Host "  Received before: $($rule.ReceivedBeforeDate)" -ForegroundColor Gray 
        }
        if ($rule.MessageTypeMatches) { 
            Write-Host "  Message type: $($rule.MessageTypeMatches)" -ForegroundColor Gray 
        }
        
        Write-Host "`nDETECTION REASON: $($rule.Reasons)" -ForegroundColor Magenta
    }
    
    Write-Host "`n========================================`n" -ForegroundColor Cyan
    
    Export-ToCSV -Data $suspiciousRules -DefaultFileName "InboxRuleHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    
    return $suspiciousRules
}

function Remove-SuspiciousInboxRules {
    param([array]$Rules)
    
    if ($Rules.Count -eq 0) {
        Write-Log "No rules to remove" -Level INFO
        return
    }
    
    Write-Host "`nWARNING: About to delete $($Rules.Count) rules!" -ForegroundColor Red
    $confirmation = Read-Host "Type 'DELETE' to confirm"
    
    if ($confirmation -ne 'DELETE') {
        Write-Log "Cancelled" -Level INFO
        return
    }
    
    Write-Log "Removing $($Rules.Count) rules..." -Level INFO
    
    $removed = 0
    $failed = 0
    $results = @()
    
    foreach ($rule in $Rules) {
        try {
            Remove-InboxRule -Mailbox $rule.Mailbox -Identity $rule.RuleIdentity -Confirm:$false -ErrorAction Stop
            Write-Log "Removed '$($rule.RuleName)' from $($rule.Mailbox)" -Level SUCCESS
            $removed++
            $results += [PSCustomObject]@{
                Status   = "SUCCESS"
                Mailbox  = $rule.Mailbox
                RuleName = $rule.RuleName
                Error    = ""
            }
        }
        catch {
            Write-Log "Failed to remove '$($rule.RuleName)': $_" -Level ERROR
            $failed++
            $results += [PSCustomObject]@{
                Status   = "FAILED"
                Mailbox  = $rule.Mailbox
                RuleName = $rule.RuleName
                Error    = $_.Exception.Message
            }
        }
    }
    
    Write-Log "Complete. Removed: $removed, Failed: $failed" -Level SUCCESS
    Export-ToCSV -Data $results -DefaultFileName "RuleRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

function Start-InboxRuleHunt {
    Write-Host "`n=== Inbox Rule Hunt ===" -ForegroundColor Cyan
    Write-Host "Use wildcards (*) for patterns`n"
    
    $mailboxFilter = Read-Host "Mailbox filter (or blank for all)"
    $ruleName = Read-Host "Rule name pattern"
    $description = Read-Host "Description pattern"
    
    Write-Host "`nAction types:"
    Write-Host "  1. ForwardTo"
    Write-Host "  2. RedirectTo"
    Write-Host "  3. DeleteMessage"
    Write-Host "  4. MoveToFolder"
    Write-Host "  5. MarkAsRead"
    Write-Host "  6. All/Any"
    $actionChoice = Read-Host "Select (1-6, or blank)"
    
    $actionType = switch ($actionChoice) {
        '1' { 'ForwardTo' }
        '2' { 'RedirectTo' }
        '3' { 'DeleteMessage' }
        '4' { 'MoveToFolder' }
        '5' { 'MarkAsRead' }
        default { $null }
    }
    
    $enabledOnly = (Read-Host "Enabled rules only? (y/n)") -eq 'y'
    
    $results = Get-SuspiciousInboxRules -RuleNamePattern $ruleName -ActionType $actionType -EnabledOnly:$enabledOnly -DescriptionPattern $description -MailboxFilter $mailboxFilter
    
    if ($results) {
        Write-Host ""
        $removeChoice = Read-Host "Remove these rules? (y/n or Enter to skip)"
        if ($removeChoice -eq 'y') {
            Remove-SuspiciousInboxRules -Rules $results
        }
    }
}
#endregion

#region Email Search and Purge
function Get-UniqueMailboxCount {
    param([string]$SuccessResults)
    
    if (-not $SuccessResults) { return 0 }
    
    $mailboxesWithHits = @()
    $SuccessResults -split ';' | ForEach-Object {
        if ($_ -match 'Location:\s*([^\s,]+).*?Item count:\s*(\d+)') {
            $location = $matches[1].Trim()
            $itemCount = [int]$matches[2]
            if ($itemCount -gt 0) {
                $mailboxesWithHits += $location
            }
        }
    }
    
    return ($mailboxesWithHits | Select-Object -Unique).Count
}

function Start-BatchEmailSearch {
    param(
        [string]$QueryString,
        [string]$SearchNamePrefix,
        [int]$BatchSize = 750,
        [string]$Recipient
    )
    
    Write-Log "Starting batch search..." -Level INFO
    
    try {
        if ($Recipient -and $Recipient -notlike '*`**') {
            $allMailboxes = @(Get-Mailbox -Identity $Recipient -ErrorAction Stop)
        }
        else {
            $allMailboxes = Get-CachedMailboxes
        }
        
        if (-not $allMailboxes) {
            Write-Log "No mailboxes found" -Level ERROR
            return $null
        }
        
        $totalMailboxes = $allMailboxes.Count
        $numberOfBatches = [Math]::Ceiling($totalMailboxes / $BatchSize)
        Write-Log "Splitting $totalMailboxes mailboxes into $numberOfBatches batches" -Level INFO
        
        $allResults = @()
        $batchNum = 0

        for ($i = 0; $i -lt $totalMailboxes; $i += $BatchSize) {
            $batchNum++
            $batch = $allMailboxes | Select-Object -Skip $i -First $BatchSize
            $batchMailboxes = $batch.UserPrincipalName
            $batchSearchName = "$SearchNamePrefix-Batch$batchNum"
            
            Write-Log "Processing batch $batchNum/$numberOfBatches ($($batchMailboxes.Count) mailboxes)..." -Level INFO
            
            try {
                New-ComplianceSearch -Name $batchSearchName -ExchangeLocation $batchMailboxes -ContentMatchQuery $QueryString -ErrorAction Stop | Out-Null
                Start-ComplianceSearch -Identity $batchSearchName -ErrorAction Stop
                
                do {
                    Start-Sleep -Seconds 5
                    $searchStatus = Get-ComplianceSearch -Identity $batchSearchName -ErrorAction Stop
                    Write-Host "Batch $batchNum status: $($searchStatus.Status)`r" -NoNewline
                } while ($searchStatus.Status -in @('Starting', 'InProgress'))
                
                Write-Host ""
                
                if ($searchStatus.Status -eq 'Completed') {
                    $allResults += $searchStatus
                    Write-Log "Batch $batchNum complete: $($searchStatus.Items) items" -Level SUCCESS
                }
                else {
                    Write-Log "Batch $batchNum failed: $($searchStatus.Status)" -Level ERROR
                }
            }
            catch {
                Write-Log "Batch $batchNum error: $_" -Level ERROR
                continue
            }
        }
        
        $totalItems = ($allResults | Measure-Object -Property Items -Sum).Sum
        $totalSize = 0
        foreach ($result in $allResults) {
            if ($result.Size -match '(\d+)') {
                $totalSize += [long]$matches[1]
            }
        }
        
        $uniqueMailboxCount = 0
        foreach ($result in $allResults) {
            $uniqueMailboxCount += Get-UniqueMailboxCount -SuccessResults $result.SuccessResults
        }
        
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "BATCH SEARCH COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Batches: $numberOfBatches"
        Write-Host "Mailboxes Searched: $totalMailboxes"
        Write-Host "Items Found: $totalItems"
        Write-Host "Total Size: $totalSize bytes"
        Write-Host "Mailboxes with Hits: $uniqueMailboxCount"
        Write-Host ""
        
        Export-ToCSV -Data ($allResults | Select-Object Name, Status, Items, Size) -DefaultFileName "BatchSearch_$SearchNamePrefix"
        
        if ($totalItems -gt 0) {
            Write-Host "Purge Options:" -ForegroundColor Yellow
            Write-Host "  1. Soft Delete (recoverable)"
            Write-Host "  2. Hard Delete (permanent)"
            Write-Host "  3. Skip"
            
            $purgeChoice = Read-Host "`nSelect (1-3)"
            
            $purgeType = switch ($purgeChoice) {
                '1' { 
                    if ((Read-Host "Type 'SOFT-DELETE' to confirm") -eq 'SOFT-DELETE') { 'SoftDelete' } else { $null }
                }
                '2' { 
                    Write-Host "WARNING: PERMANENT DELETION!" -ForegroundColor Red
                    if ((Read-Host "Type 'HARD-DELETE' to confirm") -eq 'HARD-DELETE') { 'HardDelete' } else { $null }
                }
                default { $null }
            }
            
            if ($purgeType) {
                foreach ($result in $allResults) {
                    if ($result.Items -gt 0) {
                        Invoke-EmailPurge -SearchName $result.Name -PurgeType $purgeType
                    }
                }
                Write-Log "Batch purge complete" -Level SUCCESS
            }
        }
        
        return $allResults
    }
    catch {
        Write-Log "Batch search error: $_" -Level ERROR
        return $null
    }
}

function Start-EmailSearchAndPurge {
    Write-Host "`n=== Email Search and Purge ===" -ForegroundColor Cyan
    Write-Host "Use wildcards (*) for patterns`n"
    
    $sender = Read-Host "Sender (or blank)"
    $subject = Read-Host "Subject pattern"
    $recipient = Read-Host "Recipient (or blank for all)"
    
    Write-Host "`nDate range:"
    Write-Host "  1. Last 24 hours"
    Write-Host "  2. Last 7 days"
    Write-Host "  3. Last 30 days"
    Write-Host "  4. Custom"
    $dateChoice = Read-Host "Select (1-4)"
    
    $startDate = switch ($dateChoice) {
        '1' { (Get-Date).AddDays(-1) }
        '2' { (Get-Date).AddDays(-7) }
        '3' { (Get-Date).AddDays(-30) }
        '4' {
            try {
                [DateTime]::ParseExact((Read-Host "Start date (MM/DD/YYYY)"), "MM/dd/yyyy", $null)
            }
            catch {
                Write-Log "Invalid date, using 7 days" -Level WARNING
                (Get-Date).AddDays(-7)
            }
        }
        default { (Get-Date).AddDays(-7) }
    }
    
    $endDate = Get-Date
    
    $kqlParts = @()
    if ($sender) { $kqlParts += "from:$sender" }
    if ($subject) { $kqlParts += "subject:$subject" }
    if ($recipient) { $kqlParts += "to:$recipient" }
    $kqlParts += "received>=$($startDate.ToString('yyyy-MM-dd'))"
    $kqlParts += "received<=$($endDate.ToString('yyyy-MM-dd'))"
    
    $queryString = $kqlParts -join ' AND '
    
    Write-Host "`nQuery: $queryString" -ForegroundColor Yellow
    Write-Host "Range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))`n" -ForegroundColor Yellow
    
    if ((Read-Host "Proceed? (y/n)") -ne 'y') {
        Write-Log "Cancelled" -Level INFO
        return
    }
    
    $useBatchSearch = $false
    $batchSize = 750
    
    if (-not $recipient -or $recipient -like '*`**') {
        $mailboxes = Get-CachedMailboxes
        $mailboxCount = $mailboxes.Count
        
        if ($mailboxCount -gt 1000) {
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "LARGE TENANT: $mailboxCount mailboxes" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host "Single searches limited to 1000 mailboxes"
            Write-Host "Batch mode recommended`n" -ForegroundColor Yellow
            
            if ((Read-Host "Use batch mode? (y/n, default y)") -ne 'n') {
                $useBatchSearch = $true
                $customSize = Read-Host "Batch size (default 750, max 999)"
                if ($customSize -match '^\d+$') {
                    $batchSize = [Math]::Min([int]$customSize, 999)
                }
            }
        }
    }
    
    $searchName = "DFIR-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "`nSearch name: $searchName" -ForegroundColor Cyan
    $customName = Read-Host "Custom name (or Enter)"
    if ($customName) { $searchName = $customName }
    
    if ($useBatchSearch) {
        Start-BatchEmailSearch -QueryString $queryString -SearchNamePrefix $searchName -BatchSize $batchSize -Recipient $recipient
        return
    }
    
    Write-Log "Creating search: $searchName" -Level INFO
    
    try {
        if ($recipient -and $recipient -notlike '*`**') {
            New-ComplianceSearch -Name $searchName -ExchangeLocation $recipient -ContentMatchQuery $queryString -ErrorAction Stop | Out-Null
        }
        else {
            New-ComplianceSearch -Name $searchName -ExchangeLocation All -ContentMatchQuery $queryString -ErrorAction Stop | Out-Null
        }
        
        Start-ComplianceSearch -Identity $searchName -ErrorAction Stop
        
        do {
            Start-Sleep -Seconds 5
            $searchStatus = Get-ComplianceSearch -Identity $searchName -ErrorAction Stop
            Write-Host "Status: $($searchStatus.Status)`r" -NoNewline
        } while ($searchStatus.Status -in @('Starting', 'InProgress'))
        
        Write-Host ""
        
        if ($searchStatus.Status -eq 'Completed') {
            Write-Log "Search complete" -Level SUCCESS
            
            $mailboxCount = Get-UniqueMailboxCount -SuccessResults $searchStatus.SuccessResults
            
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "EMAIL SEARCH RESULTS" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "Search Name: $($searchStatus.Name)"
            Write-Host "Status: $($searchStatus.Status)" -ForegroundColor Green
            Write-Host ""
            Write-Host "Items Found: $($searchStatus.Items) emails"
            Write-Host "Total Size: $($searchStatus.Size) bytes"
            Write-Host "Mailboxes with Hits: $mailboxCount"
            Write-Host ""
            Write-Host "Query: $($searchStatus.ContentMatchQuery)" -ForegroundColor Cyan
            Write-Host "Created: $($searchStatus.CreatedTime)"
            Write-Host "Last Modified: $($searchStatus.LastModifiedTime)"
            
            if ($searchStatus.Errors) {
                Write-Host "`nErrors Encountered:" -ForegroundColor Red
                Write-Host $searchStatus.Errors -ForegroundColor Red
            }
            else {
                Write-Host "`nNo Errors" -ForegroundColor Green
            }
            
            Write-Host ""
            
            $exportData = [PSCustomObject]@{
                SearchName        = $searchStatus.Name
                Status            = $searchStatus.Status
                ItemsFound        = $searchStatus.Items
                TotalSize         = $searchStatus.Size
                MailboxesWithHits = $mailboxCount
                Query             = $searchStatus.ContentMatchQuery
                Created           = $searchStatus.CreatedTime
                LastModified      = $searchStatus.LastModifiedTime
                Errors            = $searchStatus.Errors
            }
            
            Export-ToCSV -Data $exportData -DefaultFileName "EmailSearch_$searchName"
            
            if ($searchStatus.Items -gt 0) {
                Write-Host "Purge Options:" -ForegroundColor Yellow
                Write-Host "  1. Soft Delete (recoverable)"
                Write-Host "  2. Hard Delete (permanent)"
                Write-Host "  3. Export only"
                Write-Host "  4. Cancel"
                
                $purgeChoice = Read-Host "`nSelect (1-4)"
                
                switch ($purgeChoice) {
                    '1' { 
                        if ((Read-Host "Type 'SOFT-DELETE' to confirm") -eq 'SOFT-DELETE') {
                            Invoke-EmailPurge -SearchName $searchName -PurgeType 'SoftDelete'
                        }
                    }
                    '2' { 
                        Write-Host "`nWARNING: PERMANENT DELETION!" -ForegroundColor Red
                        if ((Read-Host "Type 'HARD-DELETE' to confirm") -eq 'HARD-DELETE') {
                            Invoke-EmailPurge -SearchName $searchName -PurgeType 'HardDelete'
                        }
                    }
                    '3' { 
                        $detailedData = [PSCustomObject]@{
                            SearchName      = $searchStatus.Name
                            Status          = $searchStatus.Status
                            Items           = $searchStatus.Items
                            Size            = $searchStatus.Size
                            MailboxesHits   = $mailboxCount
                            Query           = $searchStatus.ContentMatchQuery
                            DetailedResults = $searchStatus.SuccessResults
                            Errors          = $searchStatus.Errors
                        }
                        Export-ToCSV -Data $detailedData -DefaultFileName "EmailSearchDetailed_$searchName"
                    }
                    default { 
                        Write-Log "Cancelled" -Level INFO 
                    }
                }
            }
            else {
                Write-Log "No emails found" -Level INFO
            }
        }
        else {
            Write-Log "Search failed: $($searchStatus.Status)" -Level ERROR
            if ($searchStatus.Errors) {
                Write-Host "`nErrors: $($searchStatus.Errors)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Log "Search error: $_" -Level ERROR
    }
}

function Invoke-EmailPurge {
    param(
        [string]$SearchName,
        [ValidateSet('SoftDelete', 'HardDelete')]
        [string]$PurgeType
    )
    
    Write-Log "Starting $PurgeType purge: $SearchName" -Level WARNING
    
    try {
        New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $PurgeType -Confirm:$false -ErrorAction Stop | Out-Null
        
        $actionName = "$SearchName`_Purge"
        
        do {
            Start-Sleep -Seconds 5
            $actionStatus = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
            if ($actionStatus) {
                Write-Host "Purge: $($actionStatus.Status)`r" -NoNewline
            }
        } while ($actionStatus -and ($actionStatus.Status -in @('Starting', 'InProgress')))
        
        Write-Host ""
        
        if ($actionStatus.Status -eq 'Completed') {
            Write-Log "Purge complete" -Level SUCCESS
            Write-Host "`n========================================" -ForegroundColor Green
            Write-Host "PURGE OPERATION COMPLETE" -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Green
            Write-Host "Search Name: $SearchName"
            Write-Host "Purge Type: $PurgeType"
            Write-Host "Status: $($actionStatus.Status)" -ForegroundColor Green
            Write-Host "Action Name: $($actionStatus.Name)"
            Write-Host "Created: $($actionStatus.CreatedTime)"
            Write-Host "Completed: $($actionStatus.LastModifiedTime)"
            Write-Host ""
            Write-Host "Results:" -ForegroundColor Cyan
            Write-Host $actionStatus.Results -ForegroundColor Gray
            
            if ($actionStatus.Errors) {
                Write-Host "`nErrors:" -ForegroundColor Red
                Write-Host $actionStatus.Errors -ForegroundColor Red
            }
            else {
                Write-Host "`nNo Errors" -ForegroundColor Green
            }
            Write-Host ""
            
            $purgeData = [PSCustomObject]@{
                SearchName   = $SearchName
                PurgeType    = $PurgeType
                Status       = $actionStatus.Status
                ActionName   = $actionStatus.Name
                Results      = $actionStatus.Results
                Errors       = $actionStatus.Errors
                Created      = $actionStatus.CreatedTime
                LastModified = $actionStatus.LastModifiedTime
            }
            
            Export-ToCSV -Data $purgeData -DefaultFileName "Purge_$SearchName"
        }
        else {
            Write-Log "Purge failed: $($actionStatus.Status)" -Level ERROR
            if ($actionStatus.Errors) {
                Write-Host "Errors: $($actionStatus.Errors)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Log "Purge error: $_" -Level ERROR
    }
}
#endregion

#region Compliance Search Management
function Show-ComplianceSearches {
    Write-Log "Retrieving compliance searches..." -Level INFO
    
    try {
        $searches = Get-ComplianceSearch -ErrorAction Stop | Sort-Object CreatedTime -Descending
        
        if ($searches.Count -eq 0) {
            Write-Log "No searches found" -Level INFO
            return
        }
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "COMPLIANCE SEARCHES: $($searches.Count)" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        $searchList = @()
        foreach ($search in $searches) {
            $mailboxCount = Get-UniqueMailboxCount -SuccessResults $search.SuccessResults
            
            Write-Host "`n----------------------------------------" -ForegroundColor Gray
            Write-Host "Name: $($search.Name)" -ForegroundColor Yellow
            Write-Host "  Status: $($search.Status)" -ForegroundColor $(if ($search.Status -eq 'Completed') { 'Green' } else { 'Yellow' })
            Write-Host "  Items Found: $($search.Items)"
            Write-Host "  Total Size: $($search.Size)"
            Write-Host "  Mailboxes with Hits: $mailboxCount"
            Write-Host "  Created: $($search.CreatedTime)"
            Write-Host "  Last Modified: $($search.LastModifiedTime)"
            Write-Host "  Query: $($search.ContentMatchQuery)" -ForegroundColor Cyan
            
            if ($search.Errors) {
                Write-Host "  Errors: YES" -ForegroundColor Red
                Write-Host "  $($search.Errors)" -ForegroundColor Red
            }
            else {
                Write-Host "  Errors: None" -ForegroundColor Green
            }
            
            $searchList += [PSCustomObject]@{
                Name              = $search.Name
                Status            = $search.Status
                Items             = $search.Items
                Size              = $search.Size
                MailboxesWithHits = $mailboxCount
                Query             = $search.ContentMatchQuery
                Created           = $search.CreatedTime
                LastModified      = $search.LastModifiedTime
                HasErrors         = if ($search.Errors) { "YES" } else { "NO" }
                Errors            = $search.Errors
            }
        }
        
        Write-Host "`n========================================`n" -ForegroundColor Cyan
        
        Export-ToCSV -Data $searchList -DefaultFileName "ComplianceSearches_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    catch {
        Write-Log "Error retrieving searches: $_" -Level ERROR
    }
}

function Show-ComplianceSearchActions {
    Write-Log "Retrieving compliance search actions..." -Level INFO
    
    try {
        $actions = Get-ComplianceSearchAction -ErrorAction Stop | Sort-Object CreatedTime -Descending
        
        if ($actions.Count -eq 0) {
            Write-Log "No search actions found" -Level INFO
            return
        }
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "SEARCH ACTIONS: $($actions.Count)" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        $actionList = @()
        foreach ($action in $actions) {
            Write-Host "`n----------------------------------------" -ForegroundColor Gray
            Write-Host "Action: $($action.Name)" -ForegroundColor Yellow
            Write-Host "  Status: $($action.Status)" -ForegroundColor $(if ($action.Status -eq 'Completed') { 'Green' } else { 'Yellow' })
            Write-Host "  Action Type: $($action.Action)"
            Write-Host "  Search Name: $($action.SearchName)"
            Write-Host "  Created: $($action.CreatedTime)"
            Write-Host "  Last Modified: $($action.LastModifiedTime)"
            
            if ($action.Results) {
                Write-Host "  Results:" -ForegroundColor Cyan
                Write-Host "    $($action.Results)" -ForegroundColor Gray
            }
            
            if ($action.Errors) {
                Write-Host "  Errors: YES" -ForegroundColor Red
                Write-Host "  $($action.Errors)" -ForegroundColor Red
            }
            else {
                Write-Host "  Errors: None" -ForegroundColor Green
            }
            
            $actionList += [PSCustomObject]@{
                Name         = $action.Name
                Status       = $action.Status
                ActionType   = $action.Action
                SearchName   = $action.SearchName
                Created      = $action.CreatedTime
                LastModified = $action.LastModifiedTime
                Results      = $action.Results
                HasErrors    = if ($action.Errors) { "YES" } else { "NO" }
                Errors       = $action.Errors
            }
        }
        
        Write-Host "`n========================================`n" -ForegroundColor Cyan
        
        Export-ToCSV -Data $actionList -DefaultFileName "SearchActions_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    catch {
        Write-Log "Error retrieving actions: $_" -Level ERROR
    }
}

function Show-SearchDetails {
    $searchName = Read-Host "`nEnter search name"
    if (-not $searchName) {
        Write-Log "No search name provided" -Level WARNING
        return
    }
    
    try {
        $search = Get-ComplianceSearch -Identity $searchName -ErrorAction Stop
        $mailboxCount = Get-UniqueMailboxCount -SuccessResults $search.SuccessResults
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "SEARCH DETAILS" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Name: $($search.Name)" -ForegroundColor Yellow
        Write-Host "Status: $($search.Status)" -ForegroundColor $(if ($search.Status -eq 'Completed') { 'Green' } else { 'Yellow' })
        Write-Host ""
        Write-Host "Items Found: $($search.Items)"
        Write-Host "Total Size: $($search.Size)"
        Write-Host "Mailboxes with Hits: $mailboxCount"
        Write-Host ""
        Write-Host "Created: $($search.CreatedTime)"
        Write-Host "Last Modified: $($search.LastModifiedTime)"
        Write-Host "Created By: $($search.CreatedBy)"
        Write-Host "Last Modified By: $($search.LastModifiedBy)"
        Write-Host ""
        Write-Host "Query:" -ForegroundColor Yellow
        Write-Host "  $($search.ContentMatchQuery)"
        Write-Host ""
        Write-Host "Locations:" -ForegroundColor Yellow
        if ($search.ExchangeLocation) {
            $search.ExchangeLocation | ForEach-Object { Write-Host "  $_" }
        }
        else {
            Write-Host "  All mailboxes"
        }
        Write-Host ""
        
        if ($search.SuccessResults) {
            Write-Host "Success Results:" -ForegroundColor Green
            Write-Host $search.SuccessResults -ForegroundColor Gray
            Write-Host ""
        }
        
        if ($search.Errors) {
            Write-Host "Errors:" -ForegroundColor Red
            Write-Host $search.Errors -ForegroundColor Red
        }
        else {
            Write-Host "Errors: None" -ForegroundColor Green
        }
        Write-Host ""
        
        $detailData = [PSCustomObject]@{
            Name              = $search.Name
            Status            = $search.Status
            Items             = $search.Items
            Size              = $search.Size
            MailboxesWithHits = $mailboxCount
            Query             = $search.ContentMatchQuery
            Created           = $search.CreatedTime
            Modified          = $search.LastModifiedTime
            CreatedBy         = $search.CreatedBy
            ModifiedBy        = $search.LastModifiedBy
            SuccessResults    = $search.SuccessResults
            HasErrors         = if ($search.Errors) { "YES" } else { "NO" }
            Errors            = $search.Errors
        }
        
        Export-ToCSV -Data $detailData -DefaultFileName "SearchDetails_$searchName"
    }
    catch {
        Write-Log "Error retrieving search: $_" -Level ERROR
    }
}

function Manage-ComplianceSearches {
    while ($true) {
        Write-Host "`n=== Compliance Search Management ===" -ForegroundColor Cyan
        Write-Host "  1. View all searches"
        Write-Host "  2. View all search actions"
        Write-Host "  3. View search details"
        Write-Host "  4. Delete search"
        Write-Host "  5. Delete search action"
        Write-Host "  6. Back to main menu"
        
        $choice = Read-Host "`nSelect (1-6)"
        
        switch ($choice) {
            '1' { 
                Show-ComplianceSearches
                Read-Host "`nPress Enter to continue"
            }
            '2' { 
                Show-ComplianceSearchActions
                Read-Host "`nPress Enter to continue"
            }
            '3' { 
                Show-SearchDetails
                Read-Host "`nPress Enter to continue"
            }
            '4' {
                $searchName = Read-Host "`nEnter search name to delete"
                if ($searchName) {
                    $confirm = Read-Host "Delete '$searchName'? (y/n)"
                    if ($confirm -eq 'y') {
                        try {
                            Remove-ComplianceSearch -Identity $searchName -Confirm:$false -ErrorAction Stop
                            Write-Log "Deleted search: $searchName" -Level SUCCESS
                        }
                        catch {
                            Write-Log "Error deleting search: $_" -Level ERROR
                        }
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            '5' {
                $actionName = Read-Host "`nEnter action name to delete"
                if ($actionName) {
                    $confirm = Read-Host "Delete '$actionName'? (y/n)"
                    if ($confirm -eq 'y') {
                        try {
                            Remove-ComplianceSearchAction -Identity $actionName -Confirm:$false -ErrorAction Stop
                            Write-Log "Deleted action: $actionName" -Level SUCCESS
                        }
                        catch {
                            Write-Log "Error deleting action: $_" -Level ERROR
                        }
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            '6' { return }
            default { Write-Host "Invalid selection" -ForegroundColor Red }
        }
    }
}
#endregion

#region Main Menu
function Show-MainMenu {
    while ($true) {
        Write-Host ""
        Show-Banner
        $choice = Read-Host "Select (1-5)"
        
        switch ($choice) {
            '1' { 
                try {
                    Start-EmailSearchAndPurge
                }
                catch {
                    Write-Log "Error: $_" -Level ERROR
                }
                Read-Host "`nPress Enter to continue"
            }
            '2' { 
                try {
                    Start-InboxRuleHunt
                }
                catch {
                    Write-Log "Error: $_" -Level ERROR
                }
                Read-Host "`nPress Enter to continue"
            }
            '3' {
                try {
                    Manage-MailboxDelegations
                }
                catch {
                    Write-Log "Error: $_" -Level ERROR
                }
            }
            '4' {
                try {
                    Manage-ComplianceSearches
                }
                catch {
                    Write-Log "Error: $_" -Level ERROR
                }
            }
            '5' { 
                Write-Log "Exiting..." -Level INFO
                Disconnect-ExchangeServices
                return
            }
            default { 
                Write-Host "Invalid selection" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}
#endregion

#region Main Execution
try {
    Write-Log "Exchange Online DFIR Toolkit Started" -Level INFO
    
    if (-not (Install-RequiredModules)) {
        Write-Log "Required modules not available. Exiting." -Level ERROR
        exit 1
    }
    
    if (Connect-ExchangeServices) {
        Show-MainMenu
    }
    else {
        Write-Log "Connection failed. Exiting." -Level ERROR
        exit 1
    }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
finally {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        # Silent disconnect
    }
}
#endregion