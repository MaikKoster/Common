#Requires -Version 3.0

<#
    .SYNOPSIS
        Returns a list of Alias being used in the script

    .DESCRIPTION 
        Returns a list of Alias being used in the script

    .LINK
        http://maikkoster.com/
        https://github.com/MaikKoster/Common/blob/master/Tools/Check-Alias.ps1

    .NOTES
        Copyright (c) 2016 Maik Koster

        Author:  Maik Koster
        Version: 1.0
        Date:    25.03.2016

        Version History:
            1.0 - 25.03.2016 - Published script


        TODO: 

#>
[CmdLetBinding(SupportsShouldProcess)]
PARAM (
    # Specifies the name and path of the Script.
    [Parameter(Mandatory)]
    [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
    [Alias("FilePath", "ScriptPath")]
    [string[]]$Path
)


Process {

    ###############################################################################
    # Start Script
    ###############################################################################
    
    Foreach ($OriginalScript in $Path) {
        $AST = [System.Management.Automation.Language.Parser]::ParseFile($OriginalScript, [ref]$null,[ref]$Null)

        $AST.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) | 
            foreach {

                $Command = $_.CommandElements[0]

                if ($Alias = Get-Alias | where { $_.Name -eq $Command }) {

                    [PSCustomObject]@{
                    Script = $OriginalScript
                    Alias = $Alias.Name
                    Definition = $Alias.Definition
                    StartOffset = $Command.Extent.StartOffset
                    StartLineNumber = $Command.Extent.StartLineNumber
                    StartColumnNumber = $Command.Extent.StartColumnNumber
                    EndOffset = $Command.Extent.EndOffset
                    EndLineNumber = $Command.Extent.EndLineNumber
                    EndColumnNumber = $Command.Extent.EndColumnNumber
                }

            }   

        } 
    }
}
