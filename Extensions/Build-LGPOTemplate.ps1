Function Build-LGPOTemplate{
    <#

    Test Examples
    $GPO = 'DoD Windows Server 2016 MS and DC v1r3\GPOs\{19859FE3-6E1B-41E7-BDF6-E8ADE5548FD9}'
    $GptTmplPath = $GPO + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
    $MachineRegPOLPath = $GPO + "\DomainSysvol\GPO\Machine\registry.pol"
    $UserRegPOLPath = $GPO + "\DomainSysvol\GPO\User\registry.pol"
    $AuditCsvPath = $GPO + "\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,
                   Position=0)]
        $Path,
        [Parameter(Mandatory=$true,
                   Position=1)]
        $OutputPath,
        [Parameter(Mandatory=$true,
                   Position=2)]
        $OutputName,
        $Run
    )

    Begin
    {
        If(!(Test-Path $Path)){throw "[$Path] does not exist."}
        #$lgpoout = $null
        $lgpoout = "; ----------------------------------------------------------------------`n"
        $lgpoout += "; PROCESSING POLICY`n"
        $lgpoout += "; Source file:`n"
        $lgpoout += "`n"
    }

    Process
    {
        $GptTmplContent = Split-IniContent -Path $Path
        If (($GptTmplContent.Section -eq 'Registry Values').count -gt 0){
            Write-host "'Registry Values' section found in [$Path], building list...." -ForegroundColor Cyan

            $RegValueList = $GptTmplContent | Where {$_.section -eq 'Registry Values'}
            Foreach ($RegKey in $RegValueList){
                $RegKeyHive = ($RegKey.Name).Split('\')[0]
                $RegKeyPath = Split-Path ($RegKey.Name).Split('\',2)[1] -Parent
                $RegName = Split-Path $RegKey.Name -Leaf

                #The -split operator supports specifying the maximum number of sub-strings to return.
                #Some values may have additional commas in them that we don't want to split (eg. LegalNoticeText)
                [String]$RegTypeInt,[String]$RegValue = $RegKey.Value -split ',',2

                Switch($RegKeyHive){
                    MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                    USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                }

                #https://www.motobit.com/help/RegEdit/cl72.htm
                Switch($RegTypeInt){
                    0 {$RegType = 'NONE'}
                    1 {$RegType = 'SZ'}
                    2 {$RegType = 'EXPAND_SZ'}
                    3 {$RegType = 'BINARY'}
                    4 {$RegType = 'DWORD'}
                    5 {$RegType = 'DWORD_BIG_ENDIAN'}
                    6 {$RegType = 'LINK'}
                    7 {$RegType = 'MULTI_SZ'}
                }

                <#
                If(Test-Path $RegProperty\$RegKeyPath){
                    Set-ItemProperty $RegProperty\$RegKeyPath -Name $RegName -Value $RegValue -Force | Out-Null
                }
                Else{
                    New-Item -Path $RegProperty\$RegKeyPath -Force | Out-Null
                    New-ItemProperty $RegProperty\$RegKeyPath -Name $RegName -Value $RegValue -PropertyType $RegType -Force | Out-Null
                }
                #>
                Write-host "   Adding Registry: $RegProperty\$RegKeyPath\$RegName" -ForegroundColor Gray
                $lgpoout += "$LGPOHive`n"
                $lgpoout += "$RegKeyPath`n"
                $lgpoout += "$RegName`n"
                $lgpoout += "$($RegType):$RegValue`n"
                $lgpoout += "`n"
            }
        }
        Else{
            Write-host "No Registry Value were found in [$Path], skipping..." -ForegroundColor Gray
        }
    }
    End {
        $lgpoout | Out-File "$OutputPath\$OutputName.lgpo"
    }
}


Function Get-UserToSid{
    [CmdletBinding()]
    param(
        [parameter(
        Mandatory=$true, 
        Position=0,
        ParameterSetName="Domain")]
        [string] $Domain,

        [parameter(
        Mandatory=$true, 
        Position=1,
        ParameterSetName="Domain"
                    )]
        [string] $User,

        [parameter(
        Mandatory=$true, 
        Position=0,
        ParameterSetName="Local",
        ValueFromPipeline= $true
                    )]
        [string] $LocalAccount
    )
    
    #Determine which parameter set was used
    switch ($PsCmdlet.ParameterSetName){
        "Local"   {$objUser = New-Object System.Security.Principal.NTAccount("$LocalAccount")}
        "Domain"  {$objUser = New-Object System.Security.Principal.NTAccount("$Domain", "$user")}
    }

    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
    $strSID.Value
}


Function Sid-toUser($sidString)
{
 $sid = new-object System.Security.Principal.SecurityIdentifier($sidString)
 $user = $sid.Translate([System.Security.Principal.NTAccount])
 $user.value
}


Function Build-SeceditFile{
    <#


    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,
                   Position=0)]
        $GptTmplPath,
        
        [Parameter(Mandatory=$true,
                   Position=1)]
        $OutputPath,

        [Parameter(Mandatory=$true,
                   Position=2)]
        $OutputName,

        [parameter(Mandatory=$false)]
        [string] $LogFolderPath
    )

    Begin
    {
        If(!(Test-Path $Path)){throw "[$Path] does not exist."}
        $backupSeceditFile = $env:ComputerName + ".seceditbackup.inf"
        If ($LogFolderPath){
            $SeceditResults = secedit /export /cfg "$WorkingPath\$backupSeceditFile" /log "$LogFolderPath\$backupSeceditFile.log"
        }
        Else{
            $SeceditResults = secedit /export /cfg "$WorkingPath\$backupSeceditFile"
        }

        #generate start of file
        #$secedit = $null
        $secedit =  "[Unicode]`n"
        $secedit += "Unicode=yes`n"
        $secedit += "[Version]`n"
        $secedit += "signature=`"`$CHICAGO`$`"`n"
        $secedit += "Revision=1`n"

        #build array with content
        $GptTmplContent = Split-IniContent -Path $GptTmplPath

    }

    Process
    {
        #get system access section
        If (($GptTmplContent.Section -eq 'System Access').count -gt 0){
            $SystemAccessFound = $true
            Write-host "'System Access' section found in [$GptTmplPath], building list...." -ForegroundColor Cyan
            $secedit += "[System Access]`n"

            $AccessValueList = $GptTmplContent | Where {$_.section -eq 'System Access'}
            Foreach ($AccessKey in $AccessValueList){
                $AccessName = $AccessKey.Name
                $AccessValue = $AccessKey.Value
                If ($AccessName -eq "NewAdministratorName"){
                    $AccessValue = $AccessValue -replace $AccessKey.Value, "$Global:NewAdministratorName"
                }
                If ($AccessName -eq "NewGuestName"){
                    $AccessValue = $AccessValue -replace $AccessKey.Value, "$Global:NewGuestName"
                }
                $secedit += "$AccessName = $AccessValue`n"
                #$secedit += "$PrivilegeValue" 
            }
        }
        Else{
            $SystemAccessFound = $false
            Write-host "No System Access were found in [$Path], skipping..." -ForegroundColor Gray
        }

        
        
        #next get Privilege Rights section
        If (($GptTmplContent.Section -eq 'Privilege Rights').count -gt 0){
            $PrivilegeRightsFound = $true
            Write-host "'Privilege Rights' section found in [$GptTmplPath], building list...." -ForegroundColor Cyan
            $secedit += "[Privilege Rights]`n"

            $PrivilegeValueList = $GptTmplContent | Where {$_.section -eq 'Privilege Rights'}
            Foreach ($PrivilegeKey in $PrivilegeValueList){
                $PrivilegeName = $PrivilegeKey.Name
                $PrivilegeValue = $PrivilegeKey.Value

                If ($PrivilegeValue -match "ADD YOUR ENTERPRISE ADMINS|ADD YOUR DOMAIN ADMINS"){
                       
                    If($IsMachinePartOfDomain){
                        $EA_SID = Get-UserToSid -Domain $envMachineDNSDomain -User "Enterprise Admins"
                        $DA_SID = Get-UserToSid -Domain $envMachineDNSDomain -User "Domain Admins"
                        $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR ENTERPRISE ADMINS",$EA_SID
                        $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR DOMAIN ADMINS",$DA_SID
                    }
                    Else{
                        $ADMIN_SID = Get-UserToSid -LocalAccount 'Administrators'
                        $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR ENTERPRISE ADMINS",$ADMIN_SID
                        $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR DOMAIN ADMINS",$ADMIN_SID
                    }
                                                    
                }
                #split up values, get only unique values and make it a comma deliminated list again
                $temp = $PrivilegeValue -split ","
                $PrivilegeValue = $($temp | Get-Unique) -join "," 


                $secedit += "$PrivilegeName = $PrivilegeValue`n"
                #$secedit += "$PrivilegeValue" 
            }
        }
        Else{
            $PrivilegeRightsFound = $false
            Write-host "No Privilege Rights were found in [$Path], skipping..." -ForegroundColor Gray
        }

    }
    End {
        Write-host "Saved file to [$OutputPath\$OutputName.seceditapply.inf]" -ForegroundColor Gray
        $secedit | Out-File "$OutputPath\$OutputName.seceditapply.inf" -Force
    }
}
