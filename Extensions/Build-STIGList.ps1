Function Check-WindowsDefender {
<#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER $return
        
    .EXAMPLE

    .SOURCE https://gallery.technet.microsoft.com/scriptcenter/PowerShell-to-Check-if-811b83bc

    #>
    param(
        [switch]
        $return
        )

    Try { 
        $defenderOptions = Get-MpComputerStatus 
        if([string]::IsNullOrEmpty($defenderOptions)) { 
            If(!$return){Write-host "Windows Defender was not found running on the Server:" $env:computername -foregroundcolor "Green"}
        } 
        else { 
            If(!$return){
                Write-host "Windows Defender was found on the Server:" $env:computername -foregroundcolor "Cyan" 
                Write-host "   Is Windows Defender Enabled?" $defenderOptions.AntivirusEnabled 
                Write-host "   Is Windows Defender Service Enabled?" $defenderOptions.AMServiceEnabled 
                Write-host "   Is Windows Defender Antispyware Enabled?" $defenderOptions.AntispywareEnabled 
                Write-host "   Is Windows Defender OnAccessProtection Enabled?"$defenderOptions.OnAccessProtectionEnabled 
                Write-host "   Is Windows Defender RealTimeProtection Enabled?"$defenderOptions.RealTimeProtectionEnabled
            }
            Else{
                If ( 
                ($defenderOptions.AntivirusEnabled) -or 
                ($defenderOptions.AMServiceEnabled) -or 
                ($defenderOptions.AntispywareEnabled) -or 
                ($defenderOptions.OnAccessProtectionEnabled) -or 
                ($defenderOptions.RealTimeProtectionEnabled) 
                ){return $true}
            }
        } 
    } 
    Catch 
    { 
        If(!$return){Write-host "Windows Defender was not found running on the Server:" $env:computername -foregroundcolor "Green"}
        Else{return $false}
    }
}


Function Check-FirewallState{
    $Compliance = 'Non-Compliant'
    $CheckDomain = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Domain' -and $_.Enabled -eq 'True'}
    $CheckPublic = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Public' -and $_.Enabled -eq 'True'}
    $CheckPrivate = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Private' -and $_.Enabled -eq 'True'}
    if ( ($CheckDomain) -and ($CheckPublic) -and ($CheckPrivate) ) {$Compliance = 'Compliant'}
    $Compliance
}

Function Get-BitlockerStatus{
<#
    .SOURCE https://blogs.technet.microsoft.com/heyscriptingguy/2015/05/26/powershell-and-bitlocker-part-2/
    #>
    $ProtectionState = Get-WmiObject -Namespace ROOT\CIMV2\Security\Microsoftvolumeencryption -Class Win32_encryptablevolume -Filter "DriveLetter = '$env:SystemDrive'" -ErrorAction SilentlyContinue
    If($ProtectionState){
            switch ($ProtectionState.GetProtectionStatus().protectionStatus){
                ("0"){$return = "Unprotected"}
                ("1"){$return = "Protected"}
                ("2"){$return = "Uknowned"}
                default {$return = "NoReturn"}
            }
    }
    Else{
        $return = "Disabled"
    }
    return $return
}

Function Get-CredGuardStatus{
<#
    .SOURCE https://blogs.technet.microsoft.com/poshchap/2016/09/23/security-focus-check-credential-guard-status-with-powershell/
    #>
    $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    #if ($DevGuard.SecurityServicesConfigured -contains 1) {"Credential Guard configured"}
    #if ($DevGuard.SecurityServicesRunning -contains 1) {"Credential Guard running"}
    if ( ($DevGuard.SecurityServicesConfigured -contains 1) ) {return 'Enabled'}
    Else{return 'Disabled'}

}

Function Get-IISVersion{
    $IISversion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ -ErrorAction SilentlyContinue).MajorVersion
    $IISrunning = Get-WmiObject Win32_Service -Filter "name='W3SVC'"
    if($IISrunning.State -eq "Running"){return $IISversion}
}


Function Check-HyperVStatus ($OSRole){
    # Get the Hyper-V feature and store it in $hyperv
    
    Switch ($OSRole) {
	    3 { $hyperv = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).Installed
            }
	    2 { $hyperv = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).Installed
            }
	    1 { $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online -ErrorAction SilentlyContinue
            }
	    Default { }
    }

    If($hyperv){
        # Check if Hyper-V is already enabled.
        if($hyperv.State -eq "Enabled") {
            $state = 'Enabled'
        } else {
            $state = 'Disabled'
        }
    } else {
            $state = 'Not Installed'
    }
    return $state
}


Function Check-SharepointVersion{
    # https://blogs.technet.microsoft.com/stefan_gossner/2015/04/20/powershell-script-to-display-version-info-for-installed-sharepoint-product-and-language-packs/

    Param(
      # decide on whether all the sub-components belonging to the product should be shown as well
      [switch]$ShowComponents
    )

    # location in registry to get info about installed software

    $RegLoc = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall

    # Get SharePoint Products and language packs
    $Programs = $RegLoc | 
	    where-object { $_.PsPath -like "*\Office*" } | 
	    foreach {Get-ItemProperty $_.PsPath} 
    $Components = $RegLoc | 
	    where-object { $_.PsPath -like "*1000-0000000FF1CE}" } | 
	    foreach {Get-ItemProperty $_.PsPath} 

    # output either just the info about Products and Language Packs
    # or also for sub components

    if ($ShowComponents.IsPresent)
    {
	    $Programs | foreach { 
		    $_ | fl  DisplayName, DisplayVersion; 

		    $productCodes = $_.ProductCodes;
		    $Comp = @() + ($Components | 
			    where-object { $_.PSChildName -in $productCodes } | 
			    foreach {Get-ItemProperty $_.PsPath});
		    $Comp | Sort-Object DisplayName | ft DisplayName, DisplayVersion -Autosize
	    }
    }
    else
    {
	    $Programs | fl DisplayName, DisplayVersion
    }
    Return $Programs
}


Function Check-SQLVersion{
    $server = $env:COMPUTERNAME
    try {
        # Define SQL instance registry keys
        $type = [Microsoft.Win32.RegistryHive]::LocalMachine;
        $regconnection = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($type, $server) ;
        $instancekey = "SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
 
        try {
            # Open SQL instance registry key
            $openinstancekey = $regconnection.opensubkey($instancekey);
        }
        catch { $out = $server + ",No SQL registry keys found"; }
 
        # Get installed SQL instance names
        $instances = $openinstancekey.getvaluenames();
 
        # Loop through each instance found
        foreach ($instance in $instances) {
 
            # Define SQL setup registry keys
            $instancename = $openinstancekey.getvalue($instance);
            $instancesetupkey = "SOFTWARE\Microsoft\Microsoft SQL Server\" + $instancename + "\Setup"; 
 
            # Open SQL setup registry key
            $openinstancesetupkey = $regconnection.opensubkey($instancesetupkey);
 
            $edition = $openinstancesetupkey.getvalue("Edition")
 
            # Get version and convert to readable text
            $version = $openinstancesetupkey.getvalue("Version");
 
            switch -wildcard ($version) {
                "13*" {$versionname = "SQL Server 2016";}
                "12*" {$versionname = "SQL Server 2014";}
                "11*" {$versionname = "SQL Server 2012";}
                "10.5*" {$versionname = "SQL Server 2008 R2";}
                "10.4*" {$versionname = "SQL Server 2008";}
                "10.3*" {$versionname = "SQL Server 2008";}
                "10.2*" {$versionname = "SQL Server 2008";}
                "10.1*" {$versionname = "SQL Server 2008";}
                "10.0*" {$versionname = "SQL Server 2008";}
                default {$versionname = $version;}
            }

            # Output results to CSV
            $out =  $server + "," + $instancename + "," + $edition + "," + $versionname; 
            return $versionname
        }
 
    }
    catch { $out = $server + ",Could not open registry"; }  

}

Function Check-MBAMInstalled{
    if (-not (Test-Path variable:local:MbamWmiNamespace))
    {
        Try{
            Set-Variable MbamWmiNamespace -Option ReadOnly -Scope local "root\Microsoft\MBAM"
            return "Installed"
        }
        Catch{
            return "Not Installed"
        }
    }

}

Function Get-OfficeVersion{
    $version = 0
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $reg.OpenSubKey('software\Microsoft\Office').GetSubKeyNames() |% {
        if ($_ -match '(\d+)\.') {
            if ([int]$matches[1] -gt $version) {
                $version = $matches[1]
            }
        }
    }
    switch($version){
        16 {return "Office 2016"}
        15 {return "Office 2013"}
        14 {return "Office 2010"}
        default {return}
    }

}


Function Build-STIGFeatureList{
    #BUILD LIST FOR:
    #-------------------- START: ROLES AND FEATURES --------------------#
    #Detection for Workstation and ServerFeature STIGs
    $arrayFeatureNames = @()

    # Always check these:
    $arrayFeatureNames += "Default" #<-- Default domain controller policy
    $arrayFeatureNames += "PowerShell"
    $arrayFeatureNames += "Applocker"

    If(Check-WindowsDefender -return){$arrayFeatureNames += "Defender"}
    If(Check-FirewallState -eq 'Compliant'){$arrayFeatureNames += "Firewall"}
    If(Get-CredGuardStatus -eq 'Enabled'){
        $arrayFeatureNames += "Credential Guard","Cred Guard","Device Guard"}
    If(Check-MBAMInstalled -eq 'Installed'){$arrayFeatureNames += "MBAM"}

    #dynamically add IE if installed to array
    [version]$IEVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').SvcVersion
    If($IEVersion){
        [string]$IESimpleName = "Internet Explorer $($IEVersion.Major)"
        $arrayFeatureNames += "Internet Explorer",$IESimpleName,"IE","IE$($IEVersion.Major)"
    }

    #Check for Web Server IIS
    $IISState = Get-IISVersion
    If($IISState){
        $arrayFeatureNames += "IIS $IISState"
        $arrayFeatureNames += "Web Server"
    }

    # Check for Hyper-V
    $HyperVRole = Check-HyperVStatus ($envOSRoleType)
    If($HyperVRole -eq "Enabled"){
        $arrayFeatureNames += "Hyper-V"
        $arrayFeatureNames += "HyperV"
    }
    #NetFrameworkFeature

    #Check for SMBv1
    switch([string]$envOSVersionSimple){
       "10.0" {$SMB1Enabled = (Get-SmbServerConfiguration | Select EnableSMB1Protocol).EnableSMB1Protocol}
        default {$SMB1Enabled = (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath -ErrorAction SilentlyContinue}).SMB1}
    }
    If ( ($SMB1Enabled) -or ($SMB1Enabled -eq 1) ){$arrayFeatureNames += "SMBv1"}

    # rebuild array with pipe delminated to be parsed
    #--------------------- END: ROLES AND FEATURES ---------------------#

    #-------------------- START: WORKSTATION PRODUCTS --------------------#
    #Detection for Workstation Product STIGs
    $officeInstalled = Get-OfficeVersion
    If ($officeInstalled -eq "Office 13"){
        $arrayFeatureNames += "Office 13","Office System 2013","Excel 2013","Project 2013","Outlook 2013",
                                "PowerPoint 2013","Word 2013","Publisher 2013","Infopath 2013","Visio 2013",
                                "Lync 2013"
    }
    If ($officeInstalled -eq "Office 16"){
        $arrayFeatureNames += "Office 16","Office System 2016","Excel 2016","Project 2016","Outlook 2016",
                                "PowerPoint 2016","Word 2016","Publisher 2016","Infopath 2016","Visio 2016",
                                "Skype for Business 2016","OneDrive for Business 2016","Skype","OneDrive","OneNote 2016"
    }

    $chromeInstalled = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)'
    If($chromeInstalled){
        $chromeversion = (Get-Item $chromeInstalled -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
        $arrayFeatureNames += "Chrome"
    }

    #$javaInstalled
    #$adobeInstalled
    #--------------------- END: WORKSTATION PRODUCTS ---------------------#

    #-------------------- START: SERVER PRODUCTS --------------------#
    #Detection for Server Products STIGs
    $serverProductNames = @()
    
    #exchange server
    $exchangeProduct = $env:ExchangeInstallPath + "\bin\ExSetup.exe"
    If(Test-Path $exchangeProduct){
        $productProperty =  Get-ItemProperty -Path $exchangeProduct
        $productversion = $productProperty.VersionInfo.ProductVersion.Major
        $arrayFeatureNames += "Exchange","Exchange $productversion"
    }

    #$sharepointProduct
    $sharepointInstalled = Check-SharepointVersion
    If ($sharepointInstalled){
        [Version]$SPSVersion = $sharepointInstalled.DisplayVersion
        If($SPSVersion.Major -eq 15){$arrayFeatureNames += "SharePoint 2013"}
        If($SPSVersion.Major -eq 16){$arrayFeatureNames += "SharePoint 2016"}   
    }

    #$hbssProduct

    #SQLProduct

    $SQLInstalled = Check-SQLVersion
    If ($SQLInstalled){
        $sqlYear = $SQLInstalled.Split(" ")[2]
        $sqlYearSimple = $sqlYear.Substring(2)
        $sqlSvrShort = $SQLInstalled -replace $sqlYear,$sqlYearSimple
        $sqlSvrShorter = ($SQLInstalled -replace "Server","SVR").Replace(' ','')
        $sqlSvrShortest = ($sqlSvrShort -replace "Server","SVR").Replace(' ','')
        $sqlShort = ($SQLInstalled -replace "Server","").Replace('  ',' ')
        $sqlShorter = ($SQLInstalled -replace "Server","").Replace(' ','')
        $sqlShortest = ($sqlSvrShort -replace "Server","").Replace(' ','')

        $arrayFeatureNames += $SQLInstalled,$sqlSvrShort,$sqlSvrShorter,$sqlSvrShortest,$sqlShort,$sqlShorter,$sqlShortest 
    }


    #--------------------- END: SERVER PRODUCTS ---------------------#

    #COMBINED LIST
    [string]$list = $arrayFeatureNames -join '|'
    return $list
}