Function Get-FirewallState
{
	[CmdletBinding()]
	
	Param ([Parameter(Mandatory = $true)][string]$HOSTNAME)
$ErrorActionPreference = "Stop"
Try {
$FirewallBlock = {
				$content = netsh advfirewall show allprofiles
				If ($domprofile = $content | Select-String 'Domain Profile' -Context 2 | Out-String)
				{ $domainpro = ($domprofile.Substring($domprofile.Length - 9)).Trim()}
				Else { $domainpro = $null }
				If ($priprofile = $content | Select-String 'Private Profile' -Context 2 | Out-String)
				{ $privatepro = ($priprofile.Substring($priprofile.Length - 9)).Trim()}
				Else { $privatepro = $null }
				If ($pubprofile = $content | Select-String 'Public Profile' -Context 2 | Out-String)
				{ $publicpro = ($pubprofile.Substring($pubprofile.Length - 9)).Trim()}
				Else { $publicpro = $null }
				
				$FirewallObject = New-Object PSObject
				Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallDomain" -value $domainpro
				Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPrivate" -value $privatepro
				Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPublic" -value $publicpro
				$FirewallObject
			}
 
Invoke-Command -computerName $HOSTNAME -command $FirewallBlock | Select-Object FirewallDomain, FirewallPrivate, FirewallPublic
 
}
Catch
		{
       Write-Host  ($_.Exception.Message -split ' For')[0] -ForegroundColor Red
        }
}