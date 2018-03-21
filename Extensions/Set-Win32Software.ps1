<#PSScriptInfo
.GUID
	5b05dd91-2073-4bc8-b598-940e6f65e89c
.VERSION 
	1.0.0.5
.AUTHOR 
	Michael Haken
.COMPANYNAME 
	BAMCIS
.COPYRIGHT 
	(c) 2016 BAMCIS. All rights reserved.
.TAGS 
	WMI Software
.LICENSEURI 
	https://www.bamcisnetworks.net/license
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
	Fixed the check for the existince of the class after creation that reported falsely that the installation failed.
#>

<#
	.SYNOPSIS
		Creates the Win32_Software and Win32_Software64 WMI classes on the local computer or a remote computer.

	.DESCRIPTION
		The cmdlet creates two custom WMI classes for enumerating installed software from the standard registry provider. It creates a temporary mof file on the SystemDrive and calls mofcomp.exe to add the WMI class.

	.PARAMETER ComputerName
		The computer to create the custom WMI classes on. This defaults to localhost. If the target is a remote computer, Invoke-Command is used to execute the underlying function.

	.PARAMETER TempFilePath
		Where the temporary mof file is stored, this defaults to %SYSTEMDRIVE%\Win32Software_$([System.Guid]::NewGuid()).mof.

	.PARAMETER Credential
		The credential to use to connect to a remote computer. This parameter is ignored if the ComputerName is localhost, ".", or 127.0.0.1.

    .EXAMPLE
		Set-Win32Software

		Creates the two custom WMI classes on the local computer.

	.EXAMPLE
		Set-Win32Software -ComputerName server1.contoso.com -Credential (Get-Credential)

		Creates the two custom WMI classes on server1.contoso.com.

	.INPUTS
		System.String, System.String

	.OUTPUTS
		None

	.NOTES
		AUTHOR: Michael Haken
		LAST UPDATE: 1/3/2017
#>

Param
(
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [System.String]$ComputerName = "localhost",

	[Parameter(Position = 1)]
	[System.String]$TempFilePath = "$env:SYSTEMDRIVE\Win32Software_$([System.Guid]::NewGuid()).mof",

    [Parameter()]
	[ValidateNotNull()]
    [System.Management.Automation.Credential()]
	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
)

Function Set-Win32SoftwareWMIClass 
{
	<#
		.SYNOPSIS
			Creates the Win32_Software and Win32_Software64 WMI classes.

		.DESCRIPTION
			The cmdlet creates two custom WMI classes for enumerating installed software from the standard registry provider. It creates a temporary mof file on the SystemDrive and calls mofcomp.exe to add the WMI class.

		.PARAMETER TempFilePath
			Where the temporary mof file is stored, this defaults to %SYSTEMDRIVE%\Win32Software_$([System.Guid]::NewGuid()).mof.

        .EXAMPLE
			Set-Win32SoftwareWMIClass

			Creates the two custom WMI classes.

		.EXAMPLE
			Set-Win32SoftwareWMIClass -TempFilePath c:\file.mof

			Creates the two custom WMI classes and stores the temporary mof file at c:\file.mof.

		.INPUTS
			System.String

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/3/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[System.String]$TempFilePath = "$env:SYSTEMDRIVE\Win32Software_$([System.Guid]::NewGuid()).mof"
	)

    Begin
    {
        if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        {
			throw "Script must be run with administrator privileges."
		}

        $WMIClass = "Win32_Software"
        $WMIClass64 = "Win32_Software64"
    
        $FileContent = @"
#pragma namespace("\\\\.\\root\\cimv2")
#PRAGMA AUTORECOVER

[dynamic, provider("RegProv"),
ProviderClsid("{fe9af5c0-d3b6-11ce-a5b6-00aa00680c3f}"),ClassContext("local|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")]
class $WMIClass64 
{
    [key] string KeyName;
    [read, propertycontext("DisplayName")] string DisplayName;
    [read, propertycontext("DisplayVersion")] string DisplayVersion;
    [read, propertycontext("InstallDate")] string InstallDate;
    [read, propertycontext("InstallSource")] string InstallSource;
    [read, propertycontext("UninstallString")] string UninstallString;
    [read, propertycontext("Publisher")] string Publisher;
    [read, propertycontext("Version")] Uint32 Version;
    [read, propertycontext("VersionMajor")] Uint32 VersionMajor;
    [read, propertycontext("VersionMinor")] Uint32 VersionMinor;
    [read, propertycontext("EstimatedSize")] Uint32 EstimatedSize; 
};

 
[dynamic, provider("RegProv"),
ProviderClsid("{fe9af5c0-d3b6-11ce-a5b6-00aa00680c3f}"),ClassContext("local|HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")]
class $WMIClass 
{
    [key] string KeyName;
    [read, propertycontext("DisplayName")] string DisplayName;
    [read, propertycontext("DisplayVersion")] string DisplayVersion;
    [read, propertycontext("InstallDate")] string InstallDate;
    [read, propertycontext("InstallSource")] string InstallSource;
    [read, propertycontext("UninstallString")] string UninstallString;
    [read, propertycontext("Publisher")] string Publisher;
    [read, propertycontext("Version")] Uint32 Version;
    [read, propertycontext("VersionMajor")] Uint32 VersionMajor;
    [read, propertycontext("VersionMinor")] Uint32 VersionMinor; 
    [read, propertycontext("EstimatedSize")] Uint32 EstimatedSize; 
};
"@
    }

    Process
    {
		if ([System.String]::IsNullOrEmpty($TempFilePath)) 
		{
			$TempFilePath = "$env:SYSTEMDRIVE\Win32Software_$([System.Guid]::NewGuid()).mof"
		}

		Write-Verbose -Message "Creating mof file at $TempFilePath."
        Set-Content -Path $TempFilePath -Value $FileContent | Out-Null

		$InstallType = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType | Select-Object -ExpandProperty InstallationType

        $Software = Get-CimClass -ClassName $WMIClass -Namespace "root/cimv2" -ErrorAction SilentlyContinue

        if ($Software -ne $null)
        {
			Write-Verbose -Message "WMI Class $WMIClass already exists, removing."
            if ($InstallType -eq "Nano Server") 
			{
				Start-Process -FilePath "$env:SystemRoot\system32\wbem\wmic.exe" -ArgumentList @("class $WMIClass delete") -Wait | Out-Null
			}
			else 
			{
				Start-Process -FilePath "$env:SystemRoot\system32\wbem\wmic.exe" -ArgumentList @("class $WMIClass delete") -WindowStyle Hidden -Wait | Out-Null
			}
        }

        $Software64 = Get-CimClass -ClassName $WMIClass64 -Namespace "root/cimv2" -ErrorAction SilentlyContinue

        if ($Software -ne $null)
        {
			Write-Verbose -Message "WMI Class $WMIClass64 already exists, removing."
            if ($InstallType -eq "Nano Server") 
			{
				Start-Process -FilePath "$env:SystemRoot\system32\wbem\wmic.exe" -ArgumentList @("class $WMIClass64 delete") -Wait | Out-Null
			}
			else 
			{
				Start-Process -FilePath "$env:SystemRoot\system32\wbem\wmic.exe" -ArgumentList @("class $WMIClass64 delete") -WindowStyle Hidden -Wait | Out-Null
			}
        }

		Write-Verbose -Message "Starting mofcomp.exe."
		if ($InstallType -eq "Nano Server") 
		{
			Start-Process -FilePath "$env:SystemRoot\system32\wbem\mofcomp.exe" -ArgumentList @($TempFilePath) -Wait
		}
		else 
		{
			Start-Process -FilePath "$env:SystemRoot\system32\wbem\mofcomp.exe" -ArgumentList @($TempFilePath) -WindowStyle Hidden -Wait
		}

		$Counter = 0

		while ($Counter -lt 30) 
		{
			try 
			{
				Remove-Item -Path $TempFilePath -ErrorAction Stop -Force | Out-Null
				Write-Verbose -Message "Deleted temporary mof file."
				break
			}
			catch [Exception] 
			{
				$Counter++

				if ($Counter -ge 30) 
				{
					Write-Warning "Timeout waiting to delete the temporary mof file, delete manually."
					break
				}

				Start-Sleep -Seconds 1
			}
		}

		Write-Verbose -Message "Testing installation success."
		$Software = Get-CimClass -ClassName $WMIClass -Namespace "root/cimv2" -ErrorAction SilentlyContinue

        if ($Software -ne $null)
        {
            Write-Host "Creating the WMI class $WMIClass was successful." -ForegroundColor Green
        }
        else
        {
            Write-Host "There was an error creating the $WMIClass class." -ForegroundColor Red
        }

		$Software64 = Get-CimClass -ClassName $WMIClass64 -Namespace "root/cimv2" -ErrorAction SilentlyContinue

        if ($Software64 -ne $null)
        {
            Write-Host "Creating the WMI class $WMIClass64 was successful." -ForegroundColor Green
        }
        else
        {
            Write-Host "There was an error creating the $WMIClass64 class." -ForegroundColor Red
        }
    }
	
	End {
	}   
}

[bool]$Local = [System.String]::IsNullOrEmpty($ComputerName) -or `
	$ComputerName -eq "." -or `
	$ComputerName.ToLower() -eq "localhost" -or `
	$ComputerName.ToLower() -eq $ENV:COMPUTERNAME.ToLower() -or `
	$ComputerName -eq "127.0.0.1"

if ($Local)
{
	Set-Win32SoftwareWMIClass -TempFilePath $TempFilePath   
}
else
{
	Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Set-Win32SoftwareWMIClass} -ArgumentList @($TempFilePath) -Credential $Credential
}
