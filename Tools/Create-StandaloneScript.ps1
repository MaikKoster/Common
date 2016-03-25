#Requires -Version 3.0

<#
    .SYNOPSIS
        Creates a standalone version of a script

    .DESCRIPTION 
        Creates a standalone version of a script by copying the script to a new file and 
        adding all function definitions from the specified Modules.

    .EXAMPLE
    .\Create-StandaloneScript.ps1 -Path "C:\Working\ConfigMgr\TaskSequence\Import-TaskSequence.ps1" -Module "ConfigMgr"

    Create a new standalone version of a PowerShell script

    .EXAMPLE
    .\Create-StandaloneScript.ps1 -Path "C:\Working\ConfigMgr\TaskSequence\Import-TaskSequence.ps1" -Module "ConfigMgr" -PassThru

    Create a new standalone version ofa PowerShell script and return path to new file

    .EXAMPLE
    .\Create-StandaloneScript.ps1 -Path "C:\Working\ConfigMgr\TaskSequence\Import-TaskSequence.ps1" -Module "ConfigMgr" -Block "Process"

    Create a new standalone version of a PowerShell script but copy the functions to the Process block instead of the Begin block

    .LINK
        http://maikkoster.com/
        https://github.com/MaikKoster/Common/blob/master/Tools/Create-StandaloneScript.ps1

    .NOTES
        Copyright (c) 2016 Maik Koster

        Author:  Maik Koster
        Version: 1.1
        Date:    25.03.2016

        Version History:
            1.0 - 24.03.2016 - Published script
            1.1 - 25.02.2016 - Added support for #Requires
                             - Replaced Alias


        TODO: Add support for multiple Import-Command and #Requires entries

#>
[CmdLetBinding(SupportsShouldProcess)]
PARAM (
    # Specifies the name and path of the Script.
    [Parameter(Mandatory)]
    [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
    [Alias("FilePath", "ScriptPath")]
    [string[]]$Path,

    # Specifies the Module(s) that shall be merged into the script
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Module, 

    # Specifies the Script Block to which the functions shall be added.
    # Default is the "Begin" block to have the function definitions available on Process.
    # If the specified Block is not available in the specified script or "None" is set,
    # the functions will be copied to the top of the script.
    [ValidateSet("None", "Begin", "Process", "End")]
    [string]$Block = "Begin",
    
    # Specifies the subfolder name for the script copy
    [string]$Subfolder = "Standalone",

    # Defines the maximum amount of recursive iterations to find all relevant functions
    [int]$MaxIterations = 10,

    [switch]$PassThru
)


Process {

    ###############################################################################
    # Start Script
    ###############################################################################
    
    Foreach ($OriginalScript in $Path) {
        # Prepare script name and path
        Write-Verbose "Processing script file '$OriginalScript'."
        $NewPath = Join-path -Path (Split-Path $OriginalScript) -ChildPath $Subfolder
        $Filename = Split-Path $OriginalScript -Leaf
        $ScriptCopy = Join-Path -Path $NewPath -ChildPath $Filename
        Write-Verbose "Prepare path and name for script copy at '$ScriptCopy'."
        if (-not(Test-Path ($NewPath))){New-Item -Path $NewPath -ItemType Directory}

        # Get the script content as scriptblock
        Write-Verbose "Parse original script."
        $AST = [System.Management.Automation.Language.Parser]::ParseFile($OriginalScript, [ref]$null, [ref]$null)
        $Script = $AST.GetScriptBlock()

        # Get Module commands
        $ModuleCommands = $Module | Get-ModuleCommands

        # Need to loop as copied functions might call additional "external" functions 
        $ScriptCommands = @{}
        $Finished = $false
        $Count = 0
        Do {
            $Count++
            Write-Verbose "Iteration $Count"
            $ScriptCommands = Get-ScriptCommands -Script $Script -ScriptCommands $ScriptCommands -ModuleCommands $ModuleCommands
            if (($ScriptCommands -eq $null) -or (!($ScriptCommands.ContainsValue($false))) -or ($Count -ge $MaxIterations)) {
                    $Finished = $true
                    Write-Verbose "Finished copying commands."
            } else {
                $Result = Copy-Commands -Script $Script -ScriptCommands $ScriptCommands -ModuleCommands $ModuleCommands -Block $Block
                if ($Result -ne $null) {
                    $ScriptCommands = $Result.ScriptCommands
                    $Script = $Result.Script
                } else {
                    $Finished = $true
                    Write-Error "Failed to copy commands."
                }
            }
        } Until ($Finished)

        # Remove Import-Module lines
        $ScriptText = $Script.ToString()
        #Foreach ($Mod in $Module) {
            Write-Verbose "Remove 'Import-Module' entries from script."
            #$ScriptText = $ScriptText.split("`r`n") | Where-Object {$_ -notmatch "Import\-Module $Mod"}
            $ScriptText = Remove-ImportModuleCommand -Script $Script -Module $Module
        #}

        # Export Script
        if (-not([string]::IsNullOrEmpty($ScriptText))) {
            if (Test-Path $ScriptCopy) {
                Remove-Item $ScriptCopy -Force
            }
            Write-Verbose "Save standalone script copy at '$ScriptCopy'."
            $ScriptText | Out-File -FilePath $ScriptCopy -Encoding utf8 -Append -NoClobber

            # On PassThru write back the new path to the standalone script
            if ($PassThru.IsPresent) {
                $ScriptCopy
            }
        }
    }
}

Begin {
    # Removes the "Import-Module" and Requires -Modules commands from the supplied script.
    # Only the Modules specified with the Module parameter will be removed.
    function Remove-ImportModuleCommand {
        [CmdLetBinding()]
        [OutputType([string])]
        PARAM(
            # Specifies the Script from which the Import-Module commands shall be removed.
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [scriptblock]$Script,

            # Specifies the Modules which Import-Module commands shall be removed.
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string[]]$Module
        )

        Process {
            $ImportModuleCommands = @{}
            $AST = $Script.Ast

            # Get Import-Module commands
            if ($AST -ne $null) {
                $ASTCommands = $AST.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) 

                Foreach ($ASTCommand in $ASTCommands) {
                    if ($ASTCommand.InvocationOperator -ne "Ampersand") {
                        $Command = $ASTCommand.CommandElements[0]
                        if ($Command.Value -ne $null) {
                            if (($Command.Value -eq "Import-Module") -or ($Command.Value -eq "ipmo")) {
                                if ($Module.Contains($Command.Parent.CommandElements[1].Value)) {
                                    $ImportModuleCommands.Add($Command.Parent.CommandElements[1].Value, $Command.Extent.StartLineNumber)
                                }
                            }
                        } 
                    }
                }
            }

            # Replace Import-Module commands and #Requires entries
            [System.Text.StringBuilder]$StringBuilder = New-Object System.Text.StringBuilder
            $Count = 0
            $Script.ToString().Split("`n") | 
                ForEach-Object {
                    $Count++
                    if (-not($ImportModuleCommands.ContainsValue($Count))) {
                        foreach ($ModuleName In $Module) {
                            if (-not(($_.Contains("Requires")) -and  ($_.Contains($ModuleName)))) {
                                $StringBuilder.Append($_) | Out-Null
                            }
                        }
                    } else {
                        $ModuleName = ($ImportModuleCommands.GetEnumerator() | Where-Object {$_.Value -eq $Count})
                        Write-Verbose "Remove 'Import-Module $($ModuleName.Name)'."
                    }
                }

            $StringBuilder.ToString()
        }
    }

    # Copies the definition of the specified Commands to the ScriptBlock
    function Copy-Commands {
        [CmdLetBinding()]
        PARAM(
            # Specifies the Script to which the function definition should be copied to.
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [scriptblock]$Script,

            # Specifies the list of commmands that are required by the script.
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [hashtable]$ScriptCommands,

            # Specifies the list of commands from referenced Modules that might be used.
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.CommandInfo[]]$ModuleCommands,

            # Specifies the Script Block to which the functions shall be added.
            # Default is the "Begin" block to have the function definitions available on Process.
            # If the specified Block is not available in the specified script or "None" is set,
            # the functions will be copied to the top of the script. 
            [ValidateSet("None", "Begin", "Process", "End")]
            [string]$Block = "Begin"
        )

        Process {
            Write-Verbose "Copy commands to new script."
            if ($ScriptCommands.Count -gt 0) {
            
                [System.Text.StringBuilder]$ScriptText = New-Object System.Text.StringBuilder
                $ScriptText.Append($Script.ToString()) | Out-Null
                
                # Fix "Block" parameter, if "None" is specified, but Blocks do exist
                if ($Block -eq "None") {
                    if ($Script.Ast.BeginBlock -ne $null) {
                        $Block = "Begin"
                    } elseif ($Script.Ast.ProcessBlock -ne $null) {
                        $Block = "Process"
                    } elseif ($Script.Ast.EndBlock -ne $null) {
                        $Block = "End"
                    }
                }

                # Add new commands at the top of the specified Script block or at the top of the whole script
                $StartPos = 0
                switch ($Block) {
                    "Begin" {
                        if ($Script.Ast.BeginBlock -ne $null) {
                            $StartPos = $Script.Ast.BeginBlock.Extent.StartOffset +1
                            Write-Verbose "Copy to the Begin Block."
                        } 
                    }
                    "Process" {
                        if ($Script.Ast.ProcessBlock -ne $null) {
                            $StartPos = $Script.Ast.ProcessBlock.Extent.StartOffset -1
                            Write-Verbose "Copy to the Process Block."
                        } 
                    }
                    "End" {
                        if ($Script.Ast.EndBlock -ne $null) {
                            $StartPos = $Script.Ast.EndBlock.Extent.StartOffset -1
                            Write-Verbose "Copy to the End Block."
                        } 
                    }
                }

                if ($StartPos -eq 0) {
                    Write-Verbose "Copy to the beginning of the script."
                    if ($Script.Ast.ParamBlock -ne $null) {
                        # Start directly after the parameter definition
                        $StartPos = $Script.Ast.ParamBlock.Extent.EndOffset
                    }
                } else {
                    # Get position of first "{" 
                    $StartPos = ($Script.ToString()).IndexOf("{", $StartPos) + 1
                }
    
                # Copy the script commands to the script copy. 
                # Need to keep this out of the loop as the enumerator would fail when updating the hashtable
                [string[]]$Commands = $ScriptCommands.Keys
                foreach ($Command in $Commands) {
                    if ($ScriptCommands.Item($Command) -eq $false) {
                        $ModuleCommand = $ModuleCommands | Where-Object {$_.Name -eq $Command}
                        if ($ModuleCommand -ne $null) {
                            $NewCommand = Get-CommandBody -Command $ModuleCommand
                            Write-Verbose "Copy command '$Command'."
                            $ScriptText.Insert($StartPos, $NewCommand) | Out-Null
                            $StartPos += $NewCommand.Length
                            $ScriptCommands.Item($Command) = $true
                        }
                    }
                }

                [PSCustomObject]@{Script = [scriptblock]::Create($ScriptText.ToString()); ScriptCommands = $ScriptCommands}
            }
        }
    }

    # Returns a list of Commands from the specified Module(s).
    # For Script based modules, internal commands will be included as well.
    function Get-ModuleCommands {
        [CmdLetBinding()]
        [OutputType([System.Management.Automation.CommandInfo[]])]
        PARAM (
            # Specifies the name of the Module(s)
            [Parameter(Mandatory,ValueFromPipeline)]
            [ValidateNotNullOrEmpty()]
            [string]$Module
        )

        Begin {
            [System.Management.Automation.CommandInfo[]]$ModuleCommands = $null
        }

        Process {
            Write-Verbose "Get commands from Module '$Module'."
            # Get all commands from the specified Module(s).
            # For script based modules, try to get internal commands as well
            foreach ($Mod in $Module) {
                $TempModule = Import-Module $Mod -Force -PassThru
                if ($TempModule.ModuleType -eq "Script") {
                    $GetCmd = [scriptblock]::Create("Get-Command -Module $Mod")
                    $ModuleCommands += & $TempModule $GetCmd
                } else {
                    $ModuleCommands += Get-Command -Module $Mod
                }
            }

            $ModuleCommands
        }
    }

    # Returns a list of Commands from the specified ScriptBlock.
    function Get-ScriptCommands {
        [CmdLetBinding()]
        [OutputType([hashtable])]
        PARAM (
            # Specifies the script
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [scriptblock]$Script,

            # specifies a list of ModuleCommands to reference.
            # The function will limit the list of commands to the Modulecommands supplied.
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.CommandInfo[]]$ModuleCommands,

            # Specifies a list of Script commands that have been evaluated already.
            [hashtable]$ScriptCommands = @{}
        )

        Process {
            Write-Verbose "Get commands from script."
            # Parse the supplied script block
            $AST = [System.Management.Automation.Language.Parser]::ParseInput($Script, [ref]$null, [ref]$null)
            
            if ($AST -ne $null) {
                $ASTCommands = $AST.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) 

                Foreach ($ASTCommand in $ASTCommands) {
                    if ($ASTCommand.InvocationOperator -ne "Ampersand") {
                        $Command = $ASTCommand.CommandElements[0]
                        if ($Command.Value -ne $null) {
                            if (-not($ScriptCommands.ContainsKey($Command.Value))) {
                                # Check if it's a Module command
                                if ($ModuleCommands | Where-Object {$_.Name -eq $Command}) {
                                    Write-Verbose "Found new command '$Command'."
                                    $ScriptCommands.Add($Command.Value, $false)
                                } 
                            }
                        } 
                    }
                }
            }

            $ScriptCommands
        }
    }

    # Returns a full function definition as string.
    function Get-CommandBody {
        [CmdLetBinding(DefaultParameterSetName="Name")]
        [OutputType([string])]
        PARAM (
            # Specifies the name of the command to get the body for
            [Parameter(Mandatory,ParameterSetName="Name")]
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            # Specifies the function to export
            [Parameter(Mandatory,ParameterSetName="Command")]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.CommandInfo]$Command
        )

        Process {
            [System.Text.StringBuilder]$StringBuilder = New-Object System.Text.StringBuilder

            # Get Command by name 
            if (($PSCmdLet.ParameterSetName -eq "Name") -and (-not([string]::IsNullOrEmpty($Name)))) {
                $Command = Get-Command $Name
            }

            # Generate Command body
            if ($Command -ne $null) {
                Write-Verbose "Create definition for '$($Command.Name)'."
                $StringBuilder.AppendLine()  | Out-Null
                if ($Command.Description -ne $null) {
                    $StringBuilder.AppendLine($Command.Description.ToString()) | Out-Null
                }
                $StringBuilder.AppendLine("$($Command.CommandType) $($Command.Name) {") | Out-Null
                $StringBuilder.Append($Command.Definition) | Out-Null
                $StringBuilder.AppendLine("}") | Out-Null
            }

            # Return Command body a string
            $StringBuilder.ToString()
        }
    }
}
