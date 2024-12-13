$ServicesToDisable = @("Spooler", "Bluetooth", "w3svc")
$UnsecureServices = @("telnet", "ftp", "tftp")
function SectionHeader {
    param ([string]$Title)
    Write-Host "`n=============================`n$Title`n============================="
}
function PromptRun {
    param (
        [string]$TaskName,
        [scriptblock]$Action
    )
    $response = Read-Host "Run $TaskName? (y/n)"
    if ($response -match '^[Yy]$') {
        & $Action
    } else {
        Write-Host "$TaskName skipped."
    }
}
function GatherSystemInfo {
    SectionHeader "System Info"
    Write-Host "Hostname: $(hostname)"
    Get-ComputerInfo | Select-Object CsName, OsName, WindowsVersion
    Get-WmiObject Win32_OperatingSystem | Select-Object @{Name='Uptime';Expression={(New-TimeSpan -Start $_.LastBootUpTime).ToString()}}
    Get-Process | Measure-Object
    Get-PSDrive | Format-Table
}
function ManageAccounts {
    SectionHeader "Account Management"
    Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, @{Name='IsAdmin';Expression={($_ | Get-LocalGroupMember -Group "Administrators") -ne $null}}
    $response = Read-Host "Remove a user? (Enter username or 'n')"
    if ($response -ne 'n') {
        Remove-LocalUser -Name $response
        Write-Host "User $response removed."
    }
}
function EnforcePasswordPolicies {
    SectionHeader "Password Policies"
    Set-LocalUser -Name Administrator -PasswordNeverExpires $false
    net accounts /maxpwage:90 /minpwage:10 /minpwlen:12 /uniquepw:5
    Write-Host "Password policies applied."
}
function UpdateSystem {
    SectionHeader "Updating System"
    Install-WindowsUpdate -AcceptAll -Install
    Write-Host "System updates applied."
}
function RemoveSoftware {
    SectionHeader "Removing Software"
    Get-WmiObject Win32_Product | Select-Object Name
    $software = Read-Host "Enter software to remove"
    if ($software) {
        Get-WmiObject Win32_Product | Where-Object {$_.Name -eq $software} | ForEach-Object {$_.Uninstall()}
        Write-Host "$software removed."
    }
}
function DisableServices {
    SectionHeader "Disabling Services"
    foreach ($service in $ServicesToDisable) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled
    }
    Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -ne "Running"} | Format-Table
}
function ConfigureFirewall {
    SectionHeader "Configuring Firewall"
    New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
    Write-Host "Firewall configured."
}
function CheckOpenPorts {
    SectionHeader "Checking Open Ports"
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table
}
function ScanUnsecureServices {
    SectionHeader "Scanning Unsecure Services"
    $found = @()
    foreach ($service in $UnsecureServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            $found += $service
        }
    }
    if ($found.Count -gt 0) {
        Write-Host "Found unsecure services: $found"
        $response = Read-Host "Disable & remove these services? (y/n)"
        if ($response -match '^[Yy]$') {
            foreach ($service in $found) {
                Stop-Service -Name $service -Force
                Set-Service -Name $service -StartupType Disabled
                Write-Host "$service disabled."
            }
        }
    } else {
        Write-Host "No unsecure services found."
    }
}
function FinalSteps {
    SectionHeader "Final Steps"
    Write-Host "Review system settings and ensure security configurations are properly applied."
}
PromptRun "System Info" { GatherSystemInfo }
PromptRun "Account Management" { ManageAccounts }
PromptRun "Password Policies" { EnforcePasswordPolicies }
PromptRun "System Update" { UpdateSystem }
PromptRun "Remove Software" { RemoveSoftware }
PromptRun "Disable Services" { DisableServices }
PromptRun "Configure Firewall" { ConfigureFirewall }
PromptRun "Check Open Ports" { CheckOpenPorts }
PromptRun "Scan Unsecure Services" { ScanUnsecureServices }
PromptRun "Final Steps" { FinalSteps }
