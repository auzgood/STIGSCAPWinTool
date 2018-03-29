#========================================================================
#
#       Title: Apply-STIGToolAdv
#     Created: 2018-02-26
#      Author: Richard tracy
#
#
# GOALS:
# Apply STIGS from Backup 
#
# 
#========================================================================
##* VARIABLE DECLARATION
## 
##   Change these variables to meet domain/local workgroup enviroment
##*===============================================
$CheckGptTmpl = $true       #This setting allows the script to parse each GptTmpl.inf within the GPO backup 
                            #Workgroup: It will change any domain SID to builtin administrator
                            #Domain: It will change any Domain SID to another Domain SID 

$ReplaceGptTmpl_EA = "ADD YOUR ENTERPRISE ADMINS"   #if found in GptTmpl.inf change value to: Enterprise Admins
$ReplaceGptTmpl_DA = "ADD YOUR DOMAIN ADMINS"       #if found in GptTmpl.inf change value to: Domain Admins
$ReplaceGptTmpl_AD = ""
$NewAdministratorName = "xAdmin"                    #if found in GptTmpl.inf change value for key: NewAdministratorName
$NewGuestName = "xGuest"                            #if found in GptTmpl.inf change value for key: NewGuestName
#*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
##*===============================================
##* CONSTANT VARIABLE DECLARATION
##*===============================================
## Variables: Domain Membership
[boolean]$IsMachinePartOfDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
[string]$envMachineWorkgroup = ''
[string]$envMachineADDomain = ''
[string]$envLogonServer = ''
[string]$MachineDomainController = ''
If ($IsMachinePartOfDomain) {
	[string]$envMachineADDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
	Try {
		[string]$envLogonServer = $env:LOGONSERVER | Where-Object { (($_) -and (-not $_.Contains('\\MicrosoftAccount'))) } | ForEach-Object { $_.TrimStart('\') } | ForEach-Object { ([Net.Dns]::GetHostEntry($_)).HostName }
		# If running in system context, fall back on the logonserver value stored in the registry
		If (-not $envLogonServer) { [string]$envLogonServer = Get-ItemProperty -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DCName' -ErrorAction 'SilentlyContinue' }
		[string]$MachineDomainController = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
	}
	Catch { }
}
Else {
	[string]$envMachineWorkgroup = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
}
[string]$envMachineDNSDomain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
[string]$envUserDNSDomain = $env:USERDNSDOMAIN | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
Try {
	[string]$envUserDomain = [Environment]::UserDomainName.ToUpper()
}
Catch { }

## OS Variables
[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = $envOS.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
[string]$envOSVersionSimple = "$envOSVersionMajor.$envOSVersionMinor"
[int32]$envOSRoleType = $envOS.ProductType
[string]$enOSVersionRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID).ReleaseId

$Dated = (Get-Date -Format yyyyMMdd)

## Variables: Script Name and Script Paths
[string]$scriptPath = $MyInvocation.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[string]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent
[string]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName

#Get required folder and File paths
[string]$ExtensionsPath = Join-Path -Path $scriptRoot -ChildPath 'Extensions'
[string]$ModulesPath = Join-Path -Path $scriptRoot -ChildPath 'Modules'
[string]$ToolsPath = Join-Path -Path $scriptRoot -ChildPath 'Tools'
[string]$TempPath = Join-Path -Path $scriptRoot -ChildPath 'Temp'
[string]$LogsPath = Join-Path -Path $scriptRoot -ChildPath 'Logs'
[string]$BackupGPOPath = Join-Path -Path $scriptRoot -ChildPath 'GPO'

[string]$workingLogPath = Join-Path -Path $LogsPath -ChildPath $env:COMPUTERNAME
    New-Item $workingLogPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
[string]$workingTempPath = Join-Path -Path $TempPath -ChildPath $env:COMPUTERNAME
    New-Item $workingTempPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null


$extensions = Get-ChildItem -Path $ExtensionsPath -Recurse -Include *.ps1
foreach($extension in $extensions){
    Try{
        Write-Host "Loading extension: $($extension.FullName)" -ForegroundColor Cyan
        Import-Module $extension.FullName -ErrorAction SilentlyContinue
    }
    Catch {
        Write-Host "Unable to import the extensions." $_.Exception.Message -ForegroundColor White -BackgroundColor Red
    }
}

$modules = Get-ChildItem -Path $ModulesPath -Recurse -Include *.psd1
foreach($module in $modules){
    Try{
        Write-Host "Loading module: $($module.FullName)" -ForegroundColor Cyan
        Import-Module $module.FullName -ErrorAction SilentlyContinue -DisableNameChecking -NoClobber
    }
    Catch {
        Write-Host "Unable to import the module." $_.Exception.Message -ForegroundColor White -BackgroundColor Red
    }
}

##*===============================================
##* MAIN ROUTINE
##*===============================================
$additionalFeatureNames = Build-STIGFeatureList

#-------------------- START: OPERATING SYSTEM NAME AND ROLE --------------------#
#Build OS simple names and roles
Switch ($envOSRoleType) {
	3 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Standard|Datacenter").Replace("Windows","").Trim()
        [string]$envOSRoleTypeName = ('MS|Member Server') 
        }
	2 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Standard|Datacenter").Replace("Windows","").Trim()
        [string]$envOSSimpleVersions = 
        [string]$envOSRoleTypeName = ('DC|Domain Controller|Domain Controllers|Domain')
        }
	1 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Home|Professional").Trim()
        [string]$envOSRoleTypeName = ('Windows|Workstation')
        
        }
	Default { [string]$envOSRoleTypeName = 'Windows' }
}


[string]$envOSSimpleName = $envOSTrimName
If ($envOSRoleType -eq 1){
    #$wksVer = $envOSSimpleName.Split(" ")[1]
    $envOSShort = $envOSSimpleName -replace " ",""
    $envOSShorter = ($envOSSimpleName -replace "Windows","WIN").Replace(' ','') + $enOSVersionRelease
    $envOSShortest = ($envOSSimpleName -replace "Windows","WIN").Replace(' ','')
}
Else{
    $serverYear = $envOSSimpleName.Split(" ")[1]
    $serverYearSimple = $serverYear.Substring(2)
    $envOSShort = $envOSSimpleName -replace $serverYear,$serverYearSimple
    $envOSShorter = ($envOSSimpleName -replace "Server","SVR").Replace(' ','')
    $envOSShortest = ($envOSShort -replace "Server","SVR").Replace(' ','')
}
$envOSSimpleNames = "$envOSSimpleName|$envOSShort|$envOSShorter|$envOSShortest"

#--------------------- END: OPERATING SYSTEM NAME AND ROLE ---------------------#

#-------------------- START: DEVIATION LIST --------------------#
# Specified Words in GPO name to be identified as policies to run at the end: Order = 4
[string]$runlastGPONames = ("Deviations|Custom|Specific|Updates")
#--------------------- END: DEVIATION LIST ---------------------#

#-------------------- START: IGNORE POLICIES -----------------------#
# Specified Words in GPO name to be identified as policies to NEVER run: Order = 0
[string]$ignoreGPONames = ("_del_|zArchive|Test")
#--------------------- END: IGNORE POLICIES ------------------------#

#-------------------- START: IGNORE SITES -----------------------#
# Specified Words in GPO name to be identified as policies to NEVER run: Order = 0
[string]$ignoreGPOSites = ("SOAR|66|JCU|724|75RR|JIB|JIATF|AVTEG|STG")
#--------------------- END: IGNORE SITES ------------------------#

#grab all policies in GPO folder and build a collection array
$GPOs = @()
Write-Host "Building GPO list, this can take a while...." -ForegroundColor Green
$BackupFolders = Get-ChildItem -Recurse -Include backup.xml -Path $BackupGPOPath -ErrorAction SilentlyContinue | %{Write-Host Examining file: $_.fullname; $_}
#$BackupFolders = Get-ChildItem -Recurse -Include backup.xml -Path $BackupGPOPath -ErrorAction SilentlyContinue

$FoundPolicies = $BackupFolders.Count
Write-Host "Found $FoundPolicies GPO policies..." -ForegroundColor Cyan
Write-Host "  Parsing Policies for [$($envOSSimpleNames.Replace('|',','))] in the name..." -ForegroundColor DarkCyan
Write-Host "  Parsing Policies for [$($envOSRoleTypeName.Replace('|',' or '))] in the name..." -ForegroundColor DarkCyan
Write-Host "  Parsing Policies for [$($additionalFeatureNames.Replace('|',','))] in the name..." -ForegroundColor DarkCyan

$RunCount = 0
$IgnoreCount = 0
$progress = 1
#loop through all policies to see if they are ignored or not based on OS, roles and features, and software installed
ForEach ($Folder in $BackupFolders){
    
    $guid = $Folder.Directory.Name
    $x = [xml](Get-Content -Path $Folder -ErrorAction SilentlyContinue)
    $dn = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
    #$results.Add($dn, $guid)
    
    Write-Progress -Activity "Processing policy $($dn)" -Status "Policy $progress of $($BackupFolders.Count)" -PercentComplete (($progress / $BackupFolders.Count) * 100)  
      
    If ( ($dn -match $ignoreGPONames) -or ($dn -match $ignoreGPOSites) ){ $RunOrder = 0;$RunCount ++}
    ElseIf (($dn -match $envOSRoleTypeName) -and ($dn -match $envOSSimpleNames) -and ($dn -notmatch $runlastGPONames) -and ($dn -notmatch $additionalFeatureNames)){$RunOrder = 1;$RunCount ++}
    ElseIf ( ($dn -match $additionalFeatureNames) -and ($dn -notmatch $runlastGPONames) ){$RunOrder = 2;$RunCount ++}
    ElseIf ( (($dn -match $envOSRoleTypeName) -or ($dn -match $envOSSimpleNames)) -and ($dn -match $runlastGPONames) ){$RunOrder = 3;$RunCount ++}
    ElseIf ( (($dn -match $additionalFeatureNames) ) -and ($dn -match $runlastGPONames) ){$RunOrder = 4;$RunCount ++}
    Else { $RunOrder = 0;$IgnoreCount ++}
        
    #build a object tbale to determine which order to run policies
    $GPOTable = New-Object -TypeName PSObject -Property ([ordered]@{
        Path    = $Folder.DirectoryName
        GUID    = "$guid"
        Name    = "$dn"
        Order   = $RunOrder
            
    })
    $GPOs += $GPOTable
    $progress++ 
}# close foreach
Write-Host "  $IgnoreCount policies are being filtered" -ForegroundColor DarkMagenta
Write-Host "  $RunCount policies will be applied to local system" -ForegroundColor DarkMagenta
#Start-Sleep 30
    
#$GPOCollecton
$additionalscripts = 0
$appliedPolicies = 0
$errorPolicies = 0
$applyProgess = 1
#applying GPO to Proper OS in order
Foreach ($GPO in $GPOs | Sort-Object Order){
    #run first
    switch($GPO.Order){
        0 {$orderLabel = "Not Applicable"}
        1 {$orderLabel = "as first group"}
        2 {$orderLabel = "as second group"}
        3 {$orderLabel = "as third group"}
        4 {$orderLabel = "as fourth group"}
    }
    
    Write-Progress -Activity "Applying policy $($GPO.name)" -Status "Policy $applyProgess of $($GPOs.Count)" -PercentComplete (($applyProgess / $GPOs.Count) * 100)

    If($GPO.Order -ne 0){
        $GptTmplPath = $GPO.Path + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
        $MachineRegPOLPath = $GPO.Path + "\DomainSysvol\GPO\Machine\registry.pol"
        $UserRegPOLPath = $GPO.Path + "\DomainSysvol\GPO\User\registry.pol"
        $AuditCsvPath = $GPO.Path + "\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"

        Write-Host "Applying [$($GPO.name)] $orderLabel..." -ForegroundColor Yellow

        $env:SEE_MASK_NOZONECHECKS = 1
        If(Test-Path $GptTmplPath){
            # Command Example: SECEDIT.EXE /configure /db secedit.sdb /cfg [path]\GptTmpl.inf /log [path]\GptTmpl.log
            #Start-Process SECEDIT.EXE -ArgumentList "/configure /db secedit.sdb /cfg ""$GptTmplPath"" /log $workingLogPath\GptTmpl.log" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_secedit.stdout" -Wait -NoNewWindow
            #parses the GptTmpl.inf for registry values and builds a text file for LGPO to run later
            Build-LGPOTemplate -Path $GptTmplPath -OutputPath $workingTempPath -OutputName "$($GPO.name)"
        }

        If(Test-Path $MachineRegPOLPath){
            # Command Example: LocalPol.exe -m -v -f [path]\registry.pol
            Start-Process "$ToolsPath\LocalGPO\Security Templates\LocalPol.exe" -ArgumentList "-m -v -f ""$MachineRegPOLPath""" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_localpol_machine.stdout" -Wait -NoNewWindow
        }

        If(Test-Path $UserRegPOLPath){
            # Command Example: LocalPol.EXE -u -v -f [path]\registry.pol
            Start-Process "$ToolsPath\LocalGPO\Security Templates\LocalPol.exe" -ArgumentList "-u -v -f ""$UserRegPOLPath""" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_localpol_user.stdout" -Wait -NoNewWindow
        }

        If(Test-Path $AuditCsvPath){
            # Command Example: AUDITPOL /restore /file:[path]\Audit.csv    
            Start-Process AUDITPOL.EXE -ArgumentList "/restore /file:""$AuditCsvPath""" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_auditpol.stdout" -Wait -NoNewWindow
        }

        Write-Host "    RUNNING COMMAND: ""$ToolsPath\LGPO.exe"" /q /v /g ""$($GPO.Path)"" >> ""$workingTempPath\$($GPO.name).stdout""" -ForegroundColor Gray
        Try{
            #Start-Process "$env:windir\system32\cscript.exe" -ArgumentList "//NOLOGO ""$ToolsPath\LocalGPO\LocalGPO.wsf"" /Path:""$($GPO.Path)"" /Validate /NoOverwrite" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_localgpo.log" -Wait -NoNewWindow
            Start-Process "$ToolsPath\LGPO.exe" -ArgumentList "/q /v /g ""$($GPO.Path)""" -RedirectStandardOutput "$workingTempPath\$($GPO.name)_lgpo.stdout" -RedirectStandardError "$workingTempPath\$($GPO.name)_lgpo.stderr" -Wait -NoNewWindow
            $appliedPolicies ++
        }
        Catch{
            Write-Host "Unable to Apply [$($GPO.name)] policy, see [$workingTempPath\$($GPO.name)_lgpo.stderr] for details" -ForegroundColor Yellow
            $errorPolicies ++
        }
        $env:SEE_MASK_NOZONECHECKS = 0
        
    }
    Else{
        Write-Host "Ignoring [$($GPO.name)] from [$($GPO.Path)] because it's [$orderLabel]..." -ForegroundColor DarkYellow
    }
    $applyProgess++
}

Write-Host "Determinig if additonal configuration eeds to be done." -ForegroundColor Cyan
If($envOSRoleType -eq 2){
    Write-Host "Extension: Applying STIG'd items for AD..." -ForegroundColor Yellow
    Set-ActiveDirectoryStigItems  | Out-File -FilePath "$workingLogPath\ADSTIGS.log"
    $additionalscripts ++
}

$IISversion = Get-IISVersion
If($IISversion){
    Write-Host "Extension: Applying STIG'd items for IIS..." -ForegroundColor Yellow
    # Get CSV files for IIS 7 Web Site STIGs
    # Change to your own files if you do not want to use the default files
    If(Get-WebConfigurationBackup -Name BeforeIISSTig){
        Remove-WebConfigurationBackup -Name BeforeIISSTig
    }
    Backup-WebConfiguration -Name BeforeIISSTig | Out-Null
    $moduleBase = (Get-Module IIS7STIGs).ModuleBase
    . "$moduleBase\ApplyIIS7STIGs.ps1" | Out-File -FilePath "$LogsPath\$env:COMPUTERNAME\IIS7STIGS.log"
    $additionalscripts ++
}


$Pendingreboot = (Get-PendingReboot).RebootPending
# Launch text
write-host ""
write-host "-----------------------------------"
write-host "|      " -NoNewLine
write-host "Apply GPO Tool Summary" -NoNewLine -ForegroundColor Green
write-host "     |"
write-host "-----------------------------------"
write-host ""
write-host "Total Policies evaluated:  " -NoNewLine
write-host $FoundPolicies -foregroundcolor Cyan
write-host "Total Policies ignored:    " -NoNewLine
write-host $IgnoreCount -foregroundcolor yellow
write-host "Total Policies applied:    " -NoNewLine
write-host $appliedPolicies -foregroundcolor green 
write-host "Total Policies errors:     " -NoNewLine
write-host $errorPolicies -foregroundcolor red
write-host "Total Scripts applied:     " -NoNewLine
write-host $additionalscripts -foregroundcolor green 
If ($Pendingreboot){write-host "Policies applied...please reboot" -ForegroundColor White -BackgroundColor Red}
Else{write-host "Policies applied..." -ForegroundColor Cyan}