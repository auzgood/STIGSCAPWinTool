 WHAT IS IT: 	A Powershell script that will take a GPO backup or SCAP XCCDF file and generate stigs settings
		Then apply them to a Windows OS using Microsoft's LGPO.exe tool from their Security Compliance Manager Toolkit

HOW TO USE IT:	There are a few methods:

			Apply-STIGToolBasic.ps1	This is a basic powershell script that will parse GPO backups and apply them based
						on hardcoded Operating Systems, features and roles

			Apply-STIGToolAdv.ps1	IN-DEVELOPMENT. This is a more dynamic powershell script. This will detect roles, 
						and features and even software and install the appropiate GPO backup.

			Apply-SCAPTool.ps1	IN-DEVELOPMENT. This is the most advanced powershell script. This script is alot 
						like linux's OpenSCAP, it will parse the XCCDF file from DISA and build a dataset
						of all STIG components. Then one by one it will apply the STIG based on the configuration files.

			Remove-STIGTool.ps1 	IN-DEVELOPMENT. This script will take the lo
						 
REQUIREMENTS:		
			To be compliant with latest STIGS, VM templates must be configured using UEFI, secureboot and virtualization (credguard)
			See screencaps in VM folder

			Stig Naming convertions is required for STIG Tools. Follow README instructions in GPO folder		

FOLDERS:
			CCI\U_CCI_List.xml <-- Used with SCAPTool.ps1. Control Correlation Identifier (CCI) provides a standard identifier and 
						description for each of the singular, actionable statements that comprise an IA control or IA best practice
			
			Configs\	   <-- Used with SCAPTool.ps1. Configuration files for each STIG ID. These are ini like files with commands for
						validation and remedation steps.
			
			Extensions\	   <-- Used with SCAPTool.ps1. Powershell extension folder provides additional PowerShell functions

			Modules\	   <-- Additional powershell modules found in PowerShell Gallery and elsewhere

			GPO\		   <-- Used with STIGToolBasic.ps1 and STIGToolAdv.ps1. Follow README instructions in folder
 
			Logs\		   <-- Output logs for LGPO and advanced logging (Use CMTRACE)

			SCAP\		   <-- SCAP Benchmark files. Follow README instructions in folder

			Temp\		   <-- Store generated LGPO config and pol files

			Tools\		   <-- Tools used in scripts, such as LGPO 

			VM\		   <-- Screenshots fo VM settings

SOURCES:		

	https://github.com/CyberSecDef/STIG
	http://www.entelechyit.com/2017/01/02/powershell-and-disa-nist-stigs-part-1/
	http://iase.disa.mil/stigs/compilations/Pages/index.aspx
	https://www.powershellgallery.com/profiles/michael.haken/
	https://github.com/alulsh/SharePoint-2013-STIGs
	https://blogs.technet.microsoft.com/matt_hinsons_manageability_blog/2016/01/29/gpo-packs-in-mdt-2013-u1-for-windows-10/
	https://www.microsoft.com/en-us/download/confirmation.aspx?id=55319
	https://github.com/search?l=PowerShell&q=STIG&type=Repositories&utf8=%E2%9C%93

