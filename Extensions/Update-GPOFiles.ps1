
Function Update-GPOFiles{
    #root path for script and files.
    $scriptPath = "c:\GPO_Deployment"

    # Create new GPO 
    write-host "Create new GPO"
    new-GPO -Name  [GPO_NAME] 

    # Backup New GPO to Named folder
    $backup = backup-gpo -Name  [GPO_NAME]   -Path $scriptPath

    #

    # Files that need to be updated:
    #  GPO_TEMPLATE_FILES\Backup.xml
    #  GPO_TEMPLATE_FILES\gpreport.xml
    #  GPO_TEMPLATE_FILES\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf

    # Create Output file structures

    $newXMLpath = New-Item -Path ("{" + $backup.Id + "}") -ItemType Directory -Force
    $newGPOinfPath = New-Item -ItemType Directory -Path ("{" + $backup.Id + "}\\DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\SecEdit") -Force

    #get the Group SIDS for the groups we created above
    $GROUP_SID =  (New-Object System.Security.Principal.NTAccount("DOMAIN", [GROUP_NAME])).Translate([System.Security.Principal.SecurityIdentifier])

    write-host "Applying tranforms to template files"

    # read inf_template file, replace sids, and write out
    $inf_template = join-path -Path ($scriptPath + "\GPO_TEMPLATE_FILES\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit") -ChildPath "GptTmpl.inf"
    $inf_outfile = Join-Path -Path $newGPOinfPath -ChildPath "GptTmpl.inf"

    (Get-Content $inf_template) | ForEach-Object {
        $_ -replace '\[GROUP_SID\]', $GROUP_SID
    } | Set-Content $inf_outfile


    # read Backup XML template file, replace sids, and write out
    $backup_template = join-path -Path ($scriptPath + "\GPO_TEMPLATE_FILES") -ChildPath "Backup.xml"
    $backup_outfile = Join-Path -Path $newXMLpath -ChildPath "Backup.xml"

    (Get-Content $backup_template) | ForEach-Object {
        $_ -replace '\[GROUP_SID\]', $GROUP_SID `
            -replace '\[GPO_NAME\]', $hostedclient
    } | Set-Content $backup_outfile


    # read GPO Report XML template file, replace sids, and write out
    $gporeport_template = join-path -Path ($scriptPath + "\GPO_TEMPLATE_FILES") -ChildPath "gpreport.xml"
    $gporeport_outfile = Join-Path -Path $newXMLpath -ChildPath "gpreport.xml"

    (Get-Content $gporeport_template) | ForEach-Object {
        $_ -replace '\[GROUP_SID\]', $GROUP_SID `
            -replace '\[GPO_NAME\]', $hostedclient
    } | Set-Content $gporeport_outfile


    Write-Host "Saving updated GPO, linking it to the new OU and moving traget web server to new OU."

    # Import GPO
    import-gpo -BackupId $backup.Id  -Path $scriptPath -TargetName [GPO_NAME]  -CreateIfNeeded 

    $updatedGPO = get-gpo  -Name [GPO_NAME]
    # Link GPO to OU 
    ## NOTE:  If you are updating an existing GPO Link, use Set-GPLink here
    New-GPLink -Guid $updatedGPO.Id -Target ("OU=[YOUR_OU],DC=domain,DC=local") -LinkEnabled Yes

    # Move web server to OU
    get-adcomputer [YOUR_SERVER] | Move-ADObject -TargetPath ("OU=[YOUR_OU],DC=domain,DC=local")


    # Add another wait for GPO to settle before forcing update.
    Write-Host "Pausing again to allow DC to catch-up again."
    start-sleep -seconds 15

    write-host "Forcing a GP Update on target webserver."

    Invoke-GPUpdate -Computer [YOUR_SERVER]
}