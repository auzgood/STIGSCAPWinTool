###### FUNCTIONS ############
Function Start-Log{
    param (
        [string]$FilePath
    )
 
    try{
        if (!(Test-Path $FilePath))
        {
             ## Create the log file
             New-Item (Split-Path $FilePath -Parent) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
             New-Item $FilePath -Type File | Out-Null
        }
 
        ## Set the global variable to be used as the FilePath for all subsequent Write-Log
        ## calls in this session
        $global:ScriptLogFilePath = $FilePath
    }
    catch{
        Write-Error $_.Exception.Message
    }
}

Function Write-Log{
    PARAM(
        [Parameter(Mandatory = $true)]
        [String]$Message,
        [string]$Component,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$Severity = 1,
        [switch]$OutputHost = $false,
        [string]$OutputHostColor
    )
    Begin{
        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        If ($Component){
            $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$Component".toupper().Replace(" ","_"), $Severity
        }
        Else{
            $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $Severity
        }
        $Line = $Line -f $LineFormat

        If ($OutputHost){
            If ($OutputHostColor){
                $Color = $OutputHostColor
            }
            Else{
                Switch ($Severity) {
				    3 { $Color = "Red" }
				    2 { $Color = "Yellow" }
				    1 { $Color = "White" }
			    }
            }
            #$OutputBoxMessage = $($OutputBoxMessage).replace("[","(").replace("]",")")
            Write-Host "`n$($Message)" -ForegroundColor $Color
        }
    }
    Process{
        Try{
        Add-Content -Value $Line -Path $global:ScriptLogFilePath
        }
        Catch{
            Write-Error $_.Exception.Message
            Exit
        }
    }
}
##*============
function Get-ListContent{
    <#
    $value = $iniContent[“386Enh"][“EGA80WOA.FON"]
    $iniContent[“386Enh"].Keys | %{$iniContent["386Enh"][$_]}
    #>
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [Parameter(Mandatory=$True)]  
        [string]$FilePath
    )
    Begin{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"
        $ini = @{}
    }
    Process{
        switch -regex -file $FilePath
        {
            "^\[(.+)\]" # Section
            {
                $section = $matches[1]
                $ini[$section] = @{}
                $CommentCount = 0
            }
            "^(;.*)$" # Comment
            {
                $value = $matches[1]
                $CommentCount = $CommentCount + 1
                $name = "Comment" + $CommentCount
                $ini[$section][$name] = $value
            } 
            "(.+?)\s*=(.*)" # Key
            {
                $name,$value = $matches[1..2]
                $ini[$section][$name] = $value
            }
        }
       return $ini
    }
    End{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    } 
}



function Set-ListContent{
    [CmdletBinding()]  
    Param(  
        [switch]$Append,
        [ValidateSet("Unicode","UTF7","UTF8","UTF32","ASCII","BigEndianUnicode","Default","OEM")]
        [Parameter()]
        [string]$Encoding = "Unicode",
        [ValidateNotNullOrEmpty()]  
        [Parameter(Mandatory=$True)]  
        [string]$FilePath,  
        [switch]$Force,
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [Hashtable]$InputObject,
        [switch]$Passthru,
        [switch]$NewLine
    )      
    Begin{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"
    }     
    Process{ 
        if ($append) {$outfile = Get-Item $FilePath}  
        else {$outFile = New-Item -ItemType file -Path $Filepath -Force:$Force -ErrorAction SilentlyContinue}  
        if (!($outFile)) {Throw "Could not create File"}  
        foreach ($i in $InputObject.keys){
            if (!($($InputObject[$i].GetType().Name) -eq "Hashtable")){
                #No Sections
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $i"
                Add-Content -Path $outFile -Value "$i=$($InputObject[$i])" -NoNewline -Encoding $Encoding

            } 
            else {
                #Sections
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing Section: [$i]" 
                $fullList = Get-ListContent $FilePath
                $sectionFound = $fullList[$i]

                #if section [] was not found add it
                If(!$sectionFound){
                    #Add-Content -Path $outFile -Value "" -Encoding $Encoding
                    Add-Content -Path $outFile -Value "[$i]" -Encoding $Encoding
                    }

                Foreach ($j in ($InputObject[$i].keys | Sort-Object)){
                    if ($j -match "^Comment[\d]+") {
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing comment: $j" 
                        Add-Content -Path $outFile -Value "$($InputObject[$i][$j])" -NoNewline -Encoding $Encoding 
                    } 
                    else {
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $j" 
                        Add-Content -Path $outFile -Value "$j=$($InputObject[$i][$j])" -NoNewline -Encoding $Encoding 
                    }
                }
                If($NewLine){Add-Content -Path $outFile -Value "" -Encoding $Encoding}
            }
        }
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Writing to file: $path"
        If($PassThru){Return $outFile}
    }
    End{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    } 
}

function Remove-ListContent{
    <#
    .SYNOPSIS
    Removes an entry/line/setting from an INI file.

    .DESCRIPTION
    A configuration file consists of sections, led by a `[section]` header and followed by `name = value` entries.  This function removes an entry in an INI file.  Something like this:

        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    Names are not allowed to contains the equal sign, `=`.  Values can contain any character.  The INI file is parsed using `Split-IniContent`.  [See its documentation for more examples.](Split-IniContent.html)

    If the entry doesn't exist, does nothing.
    Be default, operates on the INI file case-insensitively. If your INI is case-sensitive, use the `-CaseSensitive` switch.

    .LINK
    Set-IniEntry

    .LINK
    Split-IniContent

    .EXAMPLE
    Remove-IniEntry -Path C:\Projects\Carbon\StupidStupid.ini -Section rat -Name tails

    Removes the `tails` item in the `[rat]` section of the `C:\Projects\Carbon\StupidStupid.ini` file.

    .EXAMPLE
    Remove-IniEntry -Path C:\Users\me\npmrc -Name 'prefix' -CaseSensitive

    Demonstrates how to remove an INI entry in an INI file that is case-sensitive.
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the INI file.
        $Path,
        [string]
        # The name of the INI entry to remove.
        $Name,
        [string]
        # The section of the INI where the entry should be set.
        $Section,
        [Switch]
        # Removes INI entries in a case-sensitive manner.
        $CaseSensitive
    )

    $settings = @{ }

    if( Test-Path $Path -PathType Leaf ){
        $settings = Split-IniContent -Path $Path -AsHashtable -CaseSensitive:$CaseSensitive
    }
    else{
       Write-Error ('INI file {0} not found.' -f $Path)
        return
    }

    $key = $Name
    if( $Section ){
        $key = '{0}.{1}' -f $Section,$Name
    }

    if( $settings.ContainsKey( $key ) )
    {
        $lines = New-Object 'Collections.ArrayList'
        Get-Content -Path $Path | ForEach-Object { [void] $lines.Add( $_ ) }
        $null = $lines.RemoveAt( ($settings[$key].LineNumber - 1) )
        if( $PSCmdlet.ShouldProcess( $Path, ('remove INI entry {0}' -f $key) ) )
        {
            if( $lines ){
                $lines | Set-Content -Path $Path
            }
            else{
                Clear-Content -Path $Path
            }
        }
    }
}


function Split-IniContent{
    <#
    .SYNOPSIS
    Reads an INI file and returns its contents.
    
    .DESCRIPTION
    A configuration file consists of sections, led by a "[section]" header and followed by "name = value" entries:
        
        [spam]
        eggs=ham
        green=
            eggs

        [stars]
        sneetches = belly

    By default, the INI file will be returned as `Carbon.Ini.IniNode` objects for each name/value pair.  For example, given the INI file above, the following will be returned:

        Line FullName        Section Name      Value
        ---- --------        ------- ----      -----
           2 spam.eggs       spam    eggs      ham
           3 spam.green      spam    green     eggs
           7 stars.sneetches stars   sneetches belly

    It is sometimes useful to get a hashtable back of the name/values.  The `AsHashtable` switch will return a hashtable where the keys are the full names of the name/value pairs.  For example, given the INI file above, the following hashtable is returned:

        Name            Value
        ----            -----
        spam.eggs       Carbon.Ini.IniNode;
        spam.green      Carbon.Ini.IniNode;
        stars.sneetches Carbon.Ini.IniNode;
        }

    Each line of an INI file contains one entry. If the lines that follow are indented, they are treated as continuations of that entry. Leading whitespace is removed from values. Empty lines are skipped. Lines beginning with "#" or ";" are ignored and may be used to provide comments.
    Configuration keys can be set multiple times, in which case Split-IniContent will use the value that was configured last. As an example:

        [spam]
        eggs=large
        ham=serrano
        eggs=small

    This would set the configuration key named "eggs" to "small".
    It is also possible to define a section multiple times. For example:

        [foo]
        eggs=large
        ham=serrano
        eggs=small

        [bar]
        eggs=ham
        green=
           eggs

        [foo]
        ham=prosciutto
        eggs=medium
        bread=toasted

    This would set the "eggs", "ham", and "bread" configuration keys of the "foo" section to "medium", "prosciutto", and "toasted", respectively. As you can see, the only thing that matters is the last value that was set for each of the configuration keys,
    Be default, operates on the INI file case-insensitively. If your INI is case-sensitive, use the `-CaseSensitive` switch.
    .LINK
    Set-IniEntry

    .LINK
    Remove-IniEntry

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini 

    Given this INI file:
        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    `Split-IniContent` returns the following objects to the pipeline:

        Line FullName           Section    Name     Value
        ---- --------           -------    ----     -----
           2 ui.username        ui         username Regina Spektor <regina@reginaspektor.com>
           5 extensions.share   extensions share    
           6 extensions.extdiff extensions extdiff  

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini -AsHashtable

    Given this INI file:

        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    `Split-IniContent` returns the following hashtable:

        @{
            ui.username = Carbon.Ini.IniNode (
                                FullName = 'ui.username';
                                Section = "ui";
                                Name = "username";
                                Value = "Regina Spektor <regina@reginaspektor.com>";
                                LineNumber = 2;
                            );
           extensions.share = Carbon.Ini.IniNode (
                                    FullName = 'extensions.share';
                                    Section = "extensions";
                                    Name = "share"
                                    Value = "";
                                    LineNumber = 5;
                                )
            extensions.extdiff = Carbon.Ini.IniNode (
                                       FullName = 'extensions.extdiff';
                                       Section = "extensions";
                                       Name = "extdiff";
                                       Value = "";
                                       LineNumber = 6;
                                  )
        }

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini -AsHashtable -CaseSensitive

    Demonstrates how to parse a case-sensitive INI file.

        Given this INI file:

        [ui]
        username = user@example.com
        USERNAME = user2example.com

        [UI]
        username = user3@example.com

    `Split-IniContent -CaseSensitive` returns the following hashtable:

        @{
            ui.username = Carbon.Ini.IniNode (
                                FullName = 'ui.username';
                                Section = "ui";
                                Name = "username";
                                Value = "user@example.com";
                                LineNumber = 2;
                            );
            ui.USERNAME = Carbon.Ini.IniNode (
                                FullName = 'ui.USERNAME';
                                Section = "ui";
                                Name = "USERNAME";
                                Value = "user2@example.com";
                                LineNumber = 3;
                            );

            UI.username = Carbon.Ini.IniNode (
                                FullName = 'UI.username';
                                Section = "UI";
                                Name = "username";
                                Value = "user3@example.com";
                                LineNumber = 6;
                            );
        }
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='ByPath')]
        [string]
        # The path to the mercurial INI file to read.
        $Path,
        [Switch]
        # Pass each parsed setting down the pipeline instead of collecting them all into a hashtable.
        $AsHashtable,
        [Switch]
        # Parses the INI file in a case-sensitive manner.
        $CaseSensitive
    )

    if( -not (Test-Path $Path -PathType Leaf) ){
        Write-Error ("INI file '{0}' not found." -f $Path)
        return
    }

    $sectionName = ''
    $lineNum = 0
    $lastSetting = $null
    $settings = @{ }
    if( $CaseSensitive ){
        $settings = New-Object 'Collections.Hashtable'
    }

    Get-Content -Path $Path | ForEach-Object {
        $lineNum += 1

        if( -not $_ -or $_ -match '^[;#]' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }
            $lastSetting = $null
            return
        }

        if( $_ -match '^\[([^\]]+)\]' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }
            $lastSetting = $null
            $sectionName = $matches[1]
            Write-Debug "Parsed section [$sectionName]"
            return
        }

        if( $_ -match '^\s+(.*)$' -and $lastSetting ){
            $lastSetting.Value += "`n" + $matches[1]
            return
        }

        if( $_ -match '^([^=]*) ?= ?(.*)$' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }                       

            $name = $matches[1]
            $value = $matches[2]            

            $name = $name.Trim()
            $value = $value.TrimStart()   

            $setting = [pscustomobject]@{Section = $sectionName; Name = $name; Value = $value;LineNumber = $lineNum}
            #$setting = New-Object Carbon.Ini.IniNode $sectionName,$name,$value,$lineNum
            $settings[$setting.Section] = $setting
            $lastSetting = $setting
            Write-Debug "Parsed setting '$($setting.Section)'"
        }
    }

    if( $AsHashtable ){
        return $settings
    }
    else{
        if( $lastSetting ){
            $lastSetting
        }
    }
}


function Get-IniContent ($filePath)
{
    $ini = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] += $value.Trim() -split "`r`n"
        }
    }
    return $ini
}

Function Call-IniContent{
[CmdletBinding()]
    PARAM(
        # _Manual-xccdf.xml file path
        [Parameter(Mandatory=$true,
                   Position=0)]
        [xml]$Content,
        [ValidateSet('Validate', 'Remediate')]
        $Section,
        [ValidateSet('ScriptBlock', 'ScriptFile', 'Function', 'LGPO','GPTemplate')]
        $key,
        [string[]]$args,
        $results
    )
    If ($Content.$Section.$key){
        $scriptBlock = [Scriptblock]::Create($Content.$Section.$key)
        
        try{
            If($key -eq 'ScriptBlock'){$result = Invoke-Command -ScriptBlock $key }
            If($key -eq 'Function' -and $args -eq $null){$result = Invoke-Command -ScriptBlock $key}
            If($key -eq 'Function' -and $args){$result = Invoke-Command -ScriptBlock $key -ArgumentList $args}
            If($key -eq 'ScriptFile'){
                If (Test-Path "\Scripts\$key" -ErrorAction SilentlyContinue){
                    $result = . "\Scripts\$key" $args
                }
            }
            If($key -eq 'LGPO'){
                $Outfile = "$env:Temp\$($Content.Version)_LGPO.stdOut"
                $ErrorFile = "$env:Temp\$($Content.Version)_LGPO.stdError"
                $Config.$Section.LGPO | Out-File $env:Temp\LGPO.txt -Force
                $result = Start-Process .\LGPO.exe -ArgumentList "/t $env:Temp\LGPO.txt /v" -PassThru -Wait -NoNewWindow -RedirectStandardOutput $Outfile -RedirectStandardError $ErrorFile -Verbose
            }
            If($key -eq 'GPTemplate'){}

        }
        Catch {
            Write-Host "$Section $key failed to run. Check syntax " -ForegroundColor red
        }
    }

}