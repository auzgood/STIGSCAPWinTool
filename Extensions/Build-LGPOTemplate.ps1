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
    }

    Process
    {
        $GptTmplContent = Split-IniContent -Path $Path
        If (($GptTmplContent.Section -eq 'Registry Values').count -gt 0){
            Write-host "Registry Value section found, building list...." -ForegroundColor DarkYellow
            $lgpoout += "; ----------------------------------------------------------------------`n"
            $lgpoout += "; PROCESSING POLICY`n"
            $lgpoout += "; Source file:`n"
            $lgpoout += "`n"

            $RegValueList = $GptTmplContent | Where {$_.section -eq 'Registry Values'}
            Foreach ($RegKey in $RegValueList){
                $RegKeyHive = ($RegKey.Name).Split('\')[0]
                $RegKeyPath = Split-Path ($RegKey.Name).Split('\',2)[1] -Parent
                $RegName = Split-Path $RegKey.Name -Leaf
                $RegTypeInt = $RegKey.Value.Split(",")[0]
                $RegValue = $RegKey.Value.Split(",")[1]

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
                Write-host "Adding $RegProperty\$RegKeyPath\$RegName" -ForegroundColor DarkYellow
                $lgpoout += "$LGPOHive`n"
                $lgpoout += "$RegKeyPath`n"
                $lgpoout += "$RegName`n"
                $lgpoout += "$($RegType):$RegValue`n"
                $lgpoout += "`n"
            }

            $lgpoout | Out-File "$OutputPath\$OutputName.lgpo"
        }
        Else{
            Write-host "No Registry Value were found in [$Path], skipping..." -ForegroundColor Gray
        }
    }
    End {

    }
}
