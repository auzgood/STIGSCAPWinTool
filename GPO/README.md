WHAT TO DO:		Drop All GPO Backups here or download GPO from DISA (https://iase.disa.mil/stigs/gpo/Pages/index.aspx)
HOW:			Open Group Policy Management console with domain rights, and expand forest-->Domains-->[domain name]-->Group Policy Objects
				Right click Group Policy Objects-->Back Up all. Browse to a folder and give a description. Click Backup. Note any that failed. 
				The backup folder will have many GUID folders. Leave as is. Copy them to this folder
REQUIREMENTS:	GPO names within GroupPolicy Manager must be named appropiately. See Naming Convention section below
WHAT IT DOES: 	The script will read into the GPO's backup.xml inside each GUID and identifiy the name of the policy. 
				Using that information it will determine if the name matches identified system information, roles, features and install products
				and apply them locally using Microsoft's Security Compliance Manager tool LGPO. This ultimately read the GPO settings, and builds
				a file with all the registry and security settings, then applies those settings within the local gpo. These settings can then be
				viewed using the systems gpedit.msc. All keys and settings are backuped in the log folder. 

NAMING CONVENTION:
Backup folder structure does not matter. 

GPO names should be labeled to identify what its targeting. Follow these GPO naming guidelines:
		 - Computer or User Configuration does not matter, the script will apply both
		 - For Servers: Make sure you have it state at least 'Server <version>'. In addition to that make sure 'Member Server' or 'Domain Controller' is in the name
			Good Naming Examples:
				* DoD Windows Server 2016 Member Server STIG User v1r3
				* C-STIG Baseline Server 2016 MS Policy
			Bad Naming Examples:
				* Windows Server 16 Policies <-- FIX: 2016 Member Server or MS
				* Windows Server 12 DC Policies  <-- FIX: 2012

		 - For additonal role:
			Good Naming Examples: 
				* DoD Internet Explorer 11 STIG User v1r14
				* MSFT Windows 10 and Server 2016 - Credential Guard
			Bad Naming Examples:
				* Windows Server 16 Policies



Regex Matches for applied policies in beginning:
		Server [YYYY]		<-- eg: Server 2016 or Server 2012 R2
		Server [YY]		<-- eg: Server 16 or Server 12 R2
		SVR[YYYY]		<-- eg: SVR2016 or SVR2012R2
		SVR[YY]			<-- eg: SVR16 or SVR12R2
		Windows [VER]		<-- eg: Windows 10
		Windows[VER]		<-- eg: Windows10
		WIN[VER][RELEASE] 	<-- eg: WIN101703
		WIN[VER]		<-- eg: WIN10
		MS
		Member Server
		DC
		Domain Controller
		Domain Controllers
		Domain
		Windows
		Workstation
		PowerShell
		Default
		AppLocker
		Defender
		Firewall
		Credential Guard
		Cred Guard
		Device Guard
		MBAM
		SMBv1
		Office 13
		Office System 2013
		Excel 2013
		Project 2013
		Outlook 2013
		PowerPoint 2013
		Word 2013
		Publisher 2013
		Infopath 2013
		Visio 2013
		Lync 2013
		Office 16
		Office System 2016
		Excel 2016
		Project 2016
		Outlook 2016
		PowerPoint 2016
		Word 2016
		Publisher 2016
		Infopath 2016
		Visio 2016
		Skype for Business 2016
		OneDrive for Business 2016
		Skype
		Onedrive
		OneNote 2016
		Chrome
		Exchange
		SharePoint 2013
		SharePoint 2016
		SQL Server [YYYY]		<-- eg: SQL Server 2016 or SQL Server 2008 R2
		SQL Server [YY]			<-- eg: SQL Server 16 or SQL Server 08 R2
		SQLSVR[YYYY]			<-- eg: SQLSVR2016 or SQLSVR2008R2
		SQLSVR[YY]			<-- eg: SQLSVR16 or SQLSVR08R2
		SQL [YYYY]			<-- eg: SQL 2016 or SQL 2008 R2
		SQL[YYYY]			<-- eg: SQL2016 or SQL2008R2
		SQL[YY]				<-- eg: SQL16 or SQL08R2
		IIS
		IIS [ver]
		Web Server
		Hyper-V
		HyperV
		IE
		IE11				<-- eg: IE11
		Internet Explorer
		Internet Explorer [ver]		<-- eg: Internet Explorer 11

Regex Matches for applied policies at end: [Script line: 122]
		Deviations
		Custom
		Specific
		Updates

Regex Matches for ignored policies: [Script line: 128]
		_del_
		zArchive
		Test

