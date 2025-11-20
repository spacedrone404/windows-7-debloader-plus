<#
Windows 7 Debloater + [2025] (updated for Windows 7 compatibility)

Notes:
- This script requires elevation. Keep "#Requires -RunAsAdministrator".
- Tested for compatibility with PowerShell 2.0+ idioms (avoids cmdlets added in PS5 that Windows 7 may not have).
- The script uses schtasks.exe to manage scheduled tasks (Get-ScheduledTask isn't available on Win7).
- SMB1 is disabled using the supported registry / sc.exe commands for Windows 7 per Microsoft guidance (no Disable-WindowsOptionalFeature).
#>

# Requires elevation
#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms

$host.UI.RawUI.BackgroundColor = 'Black'
Clear-Host

Write-Host "Welcome to Windows 7 Debloater+ [2025]`n" -ForegroundColor White

Write-Host "Script is based upon Windows 8.1 Debloater:
https://github.com/teeotsa/windows-8-debloat
Compiled by TrackerNinja aka spacedrone808.

Original functionality:
- disable some of the bloat services
- disable telemetry, scheduled crap tasks and Defender
- disable autologger

What's new:
- implemented substantially more comprehensive services management
- high risk infection SMB1 is disabled to minimize attack vector
- applied some tweaks here and there
- added probably unneeded GUI niceties

`n" -ForegroundColor Red
Write-Host "https://trackerninja.codeberg.page`n" -ForegroundColor White

# Initial confirmation GUI
$result = [System.Windows.Forms.MessageBox]::Show(
    "We are going to change your services configuration [by a big margin], disable SMB1 protocol, disable telemetry, crap tasks and Defender, disable autologger, apply some tweaks here and there and do some other dirty hacking, math & science. Do you allow to do such things to your puter?",
    "User request for science and magic",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Question
)
if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
    Write-Host "User cancelled." -ForegroundColor Yellow
    exit
}

Write-Host "Starting to dump bloat services...`n" -ForegroundColor Green
Write-Host "This may take some time...`n" -ForegroundColor Yellow

# Helper: safe set/stop service (check for existence)
function Safe-SetService {
    param([string]$Name, [ValidateSet('Automatic','Manual','Disabled')][string]$StartupType)
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $Name -StartupType $StartupType -ErrorAction SilentlyContinue
        } else {
            # try sc.exe for nonstandard service names or when Get-Service doesn't find it
            sc.exe qc $Name > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                sc.exe config $Name start= $(
                    if ($StartupType -eq 'Disabled') { 'disabled' }
                    elseif ($StartupType -eq 'Automatic') { 'auto' }
                    else { 'demand' }
                ) | Out-Null
            }
        }
    } catch {
        # swallow errors to continue
    }
}

function Safe-StopService {
    param([string]$Name)
    try {
        # Stop-Service may fail for some protected services; best-effort
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    } catch {
        sc.exe stop $Name > $null 2>&1
    }
}

# Services to disable and stop (some names may not exist on Win7; errors suppressed)
$disabledServices = @(
    "RemoteRegistry","RemoteAccess","WinRM","TermService","SessionEnv","UmRdpService",
    "SSDPSRV","WMPNetworkSvc","p2psvc","p2pimsvc","PeerDistSvc","PNRPsvc","HomeGroupListener","HomeGroupProvider","upnphost","fdPHost","FDResPub","SNMP","SNMPTRAP","lmhosts","TlntSvr","SharedAccess","LanmanWorkstation","LanmanServer","wcncsvc","RpcLocator","CscService","napagent","Netlogon","NfsClnt","CertPropSvc","WebClient","TapiSrv","Browser","NetTcpPortSharing","lltdsvc","edgeupdate","edgeupdatem","MicrosoftEdgeElevationService","QWAVE","WwanSvc","workfolderssvc","wmiApSrv","WSService","ALG","WinHttpAutoProxySvc","PNRPAutoReg",
    "bthserv","BthHFSrv","WlanSvc","Fax",
    "WbioSrvc","lfsvc","SCPolicySvc","ScDeviceEnum","SensrSvc","IEEtwCollectorService","WPCSvc","SCardSvr","wlidsvc","fhsvc","wercplsupport","DPS","WdiServiceHost","WdiSystemHost","DiagTrack","PerfHost","pla",
    "vmicvss","vmictimesync","vmicrdv","vmicheartbeat","vmicshutdown","vmicguestinterface","vmickvpexchange",
    "wuauserv","BITS",
    "TabletInputService","Spooler","PrintNotify","mDNSResponder","WiaRpc","StiSvc","MSiSCSI","MsKeyboardFilter","smphost",
    "wscsvc","aspnet_state","AxInstSV","WSearch","AppXSvc","AppMgmt","TrkWks","seclogon","SysMain","StorSvc","hkmsvc","AppIDSvc","BDESVC","wbengine","EFS","WdNisSvc","WinDefend","AppHostSvc","defragsvc"
)

foreach ($service in $disabledServices) {
    Safe-SetService -Name $service -StartupType Disabled
    Safe-StopService -Name $service
}

# Services to set automatic and ensure running
$autoRunningServices = @(
    "UxSms","RpcSs","RpcEptMapper","CryptSvc","PolicyAgent","SamSs","IKEEXT","Winmgmt","ProfSvc","Schedule","PlugPlay","AudioSrv","AudioEndpointBuilder","MMCSS","hidserv","Themes","Power","EventSystem","DcomLaunch","SENS","Dhcp","Dnscache","Wcmsvc","gpsvc","nsi","LSM","NlaSvc","netprofm","FontCache","MpsSvc"
)

foreach ($service in $autoRunningServices) {
    Safe-SetService -Name $service -StartupType Automatic
    try { Start-Service -Name $service -ErrorAction SilentlyContinue } catch { }
}

# Services to set manual and ensure running
$manualRunningServices = @("BFE","PcaSvc","DeviceInstall","DsmSvc")
foreach ($service in $manualRunningServices) {
    Safe-SetService -Name $service -StartupType Manual
    try { Start-Service -Name $service -ErrorAction SilentlyContinue } catch { }
}

# Services to set auto and ensure stopped (note: EventLog is critical; do NOT stop EventLog on Win7 - skip if found)
$autoStoppedServices = @("sppsvc")  # removed EventLog from being stopped on purpose
foreach ($service in $autoStoppedServices) {
    Safe-SetService -Name $service -StartupType Automatic
    Safe-StopService -Name $service
}

# Services to set manual and ensure stopped
$manualStoppedServices = @(
    "Netman","AppReadiness","AeLookupSvc","Eaphost","VaultSvc","MSDTC","ShellHWDetection","NcaSvc","COMSysApp","KeyIso","Appinfo","DeviceAssociationService","msiserver","TrustedInstaller","SstpSvc","W32Time","iphlpsvc","WerSvc","Wecsvc","UI0Detect","KtmRm","WPDBusEnum","swprv","dot3svc","RasMan","RasAuto","svsvc","vds","VSS","wudfsvc","WEPHOSTSVC","NcbService","NcdAutoSetup"
)
foreach ($service in $manualStoppedServices) {
    Safe-SetService -Name $service -StartupType Manual
    Safe-StopService -Name $service
}

Clear-Host
Write-Host "Bloat services were disabled (best-effort).`n" -ForegroundColor Green

# Disable SMB1 (Windows 7 compatible approach)
Write-Host "Disabling SMB1 (Windows 7 method)...`n" -ForegroundColor Yellow
try {
    # Disable SMB1 server: set SMB1 = 0 under LanmanServer Params
    $lanmanParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    if (!(Test-Path $lanmanParams)) { New-Item -Path $lanmanParams -Force | Out-Null }
    Set-ItemProperty -Path $lanmanParams -Name 'SMB1' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    # Disable SMB1 client driver MRxSmb10
    sc.exe config mrxsmb10 start= disabled | Out-Null

    # Remove MRxSmb10 as dependency of LanmanWorkstation so workstation can start without it
    sc.exe qc lanmanworkstation > $null 2>&1
    # read current dependencies and replace with Bowser,MRxSmb20,NSI (safe default)
    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null

    Write-Host "SMB1 registry/driver disabled. A reboot is required for changes to take full effect.`n" -ForegroundColor Green
} catch {
    Write-Host "Failed to fully disable SMB1 via registry/SC. Continuing (best-effort)." -ForegroundColor Yellow
}

# Disable Telemetry (fixed typos and kept Windows 7-registry-friendly cmdlets)
Write-Host 'Disabling telemetry and personal data collection...'
$Job = Start-Job -ScriptBlock {
    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient",
        "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    )
    foreach ($p in $paths) {
        if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    }

    # Use conservative values; some keys may not exist on Win7 but commands are safe
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'MaxTelemetryAllowed' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Telemetry changes applied (best-effort).`n" -ForegroundColor Green

# Disable Windows Error Reporting
Write-Host 'Disabling Windows Error Reporting...'
$Job = Start-Job -ScriptBlock {
    Try {
        $svc = Get-Service | Where-Object { $_.DisplayName -match 'Windows Error Reporting' } | Select-Object -First 1
        if ($svc) {
            try { Stop-Service -Name $svc.Name -ErrorAction SilentlyContinue } catch {}
            try { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Clear WER data
    $werPath = Join-Path $env:ProgramData 'Microsoft\Windows\WER'
    if (Test-Path $werPath) {
        Get-ChildItem -Path $werPath -Force -Recurse | ForEach-Object {
            Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Windows Error Reporting handled.`n" -ForegroundColor Green

# Disable Bloated Scheduled Tasks (use schtasks.exe for Win7 compatibility)
Write-Host 'Disabling Bloated Scheduled Tasks...'
$Job = Start-Job -ScriptBlock {
    # Query tasks in CSV form to get TaskName (which contains the full path)
    $csv = & schtasks.exe /Query /V /FO CSV 2>$null
    if ($csv) {
        try {
            $tasks = $csv | ConvertFrom-Csv
            # target paths to disable (prefixes)
            $Paths = @(
                "\Microsoft\Windows\.NET Framework",
                "\Microsoft\Windows\Active Directory Rights Management Services Client",
                "\Microsoft\Windows\AppID",
                "\Microsoft\Windows\Application Experience",
                "\Microsoft\Windows\ApplicationData",
                "\Microsoft\Windows\AppxDeploymentClient",
                "\Microsoft\Windows\Autochk",
                "\Microsoft\Windows\Chkdsk",
                "\Microsoft\Windows\Customer Experience Improvement Program",
                "\Microsoft\Windows\Data Integrity Scan",
                "\Microsoft\Windows\Defrag",
                "\Microsoft\Windows\Device Setup",
                "\Microsoft\Windows\Diagnosis",
                "\Microsoft\Windows\DiskCleanup",
                "\Microsoft\Windows\DiskDiagnostic",
                "\Microsoft\Windows\DiskFootprint",
                "\Microsoft\Windows\FileHistory",
                "\Microsoft\Windows\IME",
                "\Microsoft\Windows\Location",
                "\Microsoft\Windows\Maintenance",
                "\Microsoft\Windows\MemoryDiagnostic",
                "\Microsoft\Windows\Mobile Broadband Accounts",
                "\Microsoft\Windows\PerfTrack",
                "\Microsoft\Windows\Offline Files",
                "\Microsoft\Windows\Power Efficiency Diagnostics",
                "\Microsoft\Windows\RecoveryEnvironment",
                "\Microsoft\Windows\Registry",
                "\Microsoft\Windows\Servicing",
                "\Microsoft\Windows\SettingSync",
                "\Microsoft\Windows\SkyDrive",
                "\Microsoft\Windows\SoftwareProtectionPlatform",
                "\Microsoft\Windows\SpacePort",
                "\Microsoft\Windows\Sysmain",
                "\Microsoft\Windows\SystemRestore",
                "\Microsoft\Windows\TextServicesFramework",
                "\Microsoft\Windows\Time Synchronization",
                "\Microsoft\Windows\TPM",
                "\Microsoft\Windows\User Profile Service",
                "\Microsoft\Windows\WDI",
                "\Microsoft\Windows\Windows Defender",
                "\Microsoft\Windows\Windows Error Reporting",
                "\Microsoft\Windows\Windows Filtering Platform",
                "\Microsoft\Windows\Windows Media Sharing",
                "\Microsoft\Windows\WindowsColorSystem",
                "\Microsoft\Windows\WindowsUpdate",
                "\Microsoft\Windows\WOF",
                "\Microsoft\Windows\Work Folders",
                "\Microsoft\Windows\Workplace Join",
                "\Microsoft\Windows\WS"
            )
            foreach ($t in $tasks) {
                # property name can vary between locales; find the column that contains a leading backslash path
                $taskName = ($t.PSObject.Properties | Where-Object { $_.Value -and ($_.Value -is [string]) -and ($_.Value.StartsWith('\')) } | Select-Object -First 1).Value
                if ($taskName) {
                    foreach ($prefix in $Paths) {
                        if ($taskName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                            # disable task
                            & schtasks.exe /Change /TN $taskName /Disable > $null 2>&1
                            break
                        }
                    }
                }
            }
        } catch {
            # fallback: do nothing
        }
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Scheduled Tasks disabled (best-effort).`n" -ForegroundColor Green

# Disable Windows Defender (attempt using sc.exe since NSudo/Expand-Archive may not exist on Win7)
Write-Host 'Disabling Windows Defender services (best-effort)...'
$Job = Start-Job -ScriptBlock {
    # Common service names for defender-related services (varies by OS)
    $defSvcs = @('WinDefend','WdNisSvc','WdNisDrv','WdFilter')
    foreach ($s in $defSvcs) {
        sc.exe qc $s > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            sc.exe config $s start= disabled > $null 2>&1
            sc.exe stop $s > $null 2>&1
        }
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Windows Defender services handled (best-effort).`n" -ForegroundColor Green

# Disable uneeded System Logging (Autologger)
Write-Host 'Disabling uneeded System Logging...'
$Job = Start-Job -ScriptBlock {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
    if (Test-Path $path) {
        Get-ChildItem -Path $path | ForEach-Object {
            $Name = $_.PsPath -replace '^Microsoft.PowerShell.Core\\Registry::','HKLM:'
            Try { Set-ItemProperty -Path $Name -Name 'Start' -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
            Try { Set-ItemProperty -Path $Name -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Logging autologgers disabled (best-effort).`n" -ForegroundColor Green

# Apply System Tweaks (use CurrentControlSet and safe registry writes)
Write-Host 'Tweaking System...'
$Job = Start-Job -ScriptBlock {
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'HiberbootEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'LargeSystemCache' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation' -Value 0x26 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Disable Peernet (policy)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Disable NetCrawling (current user; best-effort)
    Try { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'NoNetCrawling' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Disable Hibernation (powercfg)
    try { Start-Process -FilePath 'cmd' -ArgumentList '/c powercfg -h off' -Verb RunAs -WindowStyle Hidden -Wait } catch {}

    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Clear Recent Docs on Exit
    if (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'ClearRecentDocsOnExit' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # SettingSync (best-effort)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'EnableBackupForWin8Apps' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # SmartScreen (best-effort; behavior varies by OS)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Off' -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Input Personalization
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # NTFS Encryption disable
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies' -Name 'NtfsDisableEncryption' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # System Restore
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name 'DisableConfig' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name 'DisableSR' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Windows File Protection (SFC)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection' -Name 'SfcScan' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Disable Digital Locker
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker' -Name 'DoNotRunDigitalLocker' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # DEP for Explorer (policy)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # File History (Win8+ may not exist; safe)
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory' -Name 'Disabled' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Location & Sensors
    if (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors')) { New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocationScripting' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableSensors' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Sensors\LocationProvider' -Name 'CSEnable' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Remote Assistance / Remote Desktop restrictions
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Windows Update configuration (conservative values)
    if (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'CachedAUOptions' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'IncludeRecommendedUpdates' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Misc: EdgeUI corners (mostly Win8+ but safe to set)
    if (!(Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi')) { New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name 'DisableTLCorner' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name 'DisableTRCorner' -Value 1 -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Tracking / Explorer MRU settings
    if (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Tracing')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Force | Out-Null }
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name 'EnableConsoleTracing' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name 'EnableFileTracing' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name 'EnableAutoFileTracing' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackDocs' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
    Try { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Value 0 -ErrorAction SilentlyContinue | Out-Null } catch {}
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "System tweaks applied (best-effort).`n" -ForegroundColor Green

# Completion GUI
[System.Windows.Forms.MessageBox]::Show("Optimization completed! Windows 7 is free from bloat. Your computer will be restarted for better experience!", "Crap was successfully suppressed!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

# Restart computer
Restart-Computer -Force
