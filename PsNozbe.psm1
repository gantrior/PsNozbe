<#
    .Synopsis
        Uses Nozbe API and cmdlets to work with Nozbe GTD tool
#>

function Set-Key {
    param([string]$string)
    $length = $string.length
    $pad = 32-$length
    if (($length -lt 16) -or ($length -gt 32)) {Throw "String must be between 16 and 32 characters"}
    $encoding = New-Object System.Text.ASCIIEncoding
    $bytes = $encoding.GetBytes($string + "0" * $pad)
    return $bytes
}

function Set-EncryptedData {
    param($key,[string]$plainText)
    $securestring = new-object System.Security.SecureString
    $chars = $plainText.toCharArray()
    foreach ($char in $chars) {$secureString.AppendChar($char)}
    $encryptedData = ConvertFrom-SecureString -SecureString $secureString -Key $key
    return $encryptedData
}

function Get-EncryptedData {
    param($key,$data)
    $data | ConvertTo-SecureString -key $key |
    ForEach-Object {[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))}
}

function Get-Url {
[CmdletBinding()]
Param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, Position=0)]    
    [String]$Url,
    [String]$ToFile,
    [Management.Automation.PSCredential]$Credential
)
    Write-Verbose "Get-Url is considered obsolete. Please use Get-WebContent instead"

    $client = (New-Object Net.WebClient)
    if ($Credential){
        $ntwCred = $Credential.GetNetworkCredential()
        $client.Credentials = $ntwCred        
        $auth = "Basic " + [Convert]::ToBase64String([Text.Encoding]::Default.GetBytes($ntwCred.UserName + ":" + $ntwCred.Password))
        $client.Headers.Add("Authorization", $auth)
    }

    if ($ToFile -ne ""){
        $client.DownloadFile($Url, $ToFile)    
    } else {
        $client.DownloadString($Url)
    }
<#
.Synopsis
    Downloads from url as a string.
.Description     
.Parameter Url
    URL to download
.Parameter ToFile
    Optional parameter to dowload stuff to the file.
.Example
    Get-Url http://chaliy.name

    Description
    -----------
    Downloads content of the http://chaliy.name

#>
}

filter Filter-ByProperty
{
	<#
      .Synopsis
          Filters param according to wildcard filter
    #>

	Param(
		[parameter(valuefrompipeline=$true)]$InputObject,
		[parameter(mandatory=$true, position=0)][String]$property,
		[parameter(position=1)][String]$value
	)
    
    Begin 
	{
        $regex = New-Object Regex(("^" + [Regex]::Escape($value).Replace("\*", ".*").Replace("\?", ".") + "$"), [Text.RegularExpressions.RegexOptions]::IgnoreCase)
	}
	
	Process 
	{
        if ($_)
        {
            foreach ($item in $_)
            {
                if ($value)
                {
                    $match = Invoke-Expression "`$regex.IsMatch((`$item.$property))"
		            if ($match)
                    {
                        $item
                    }
                }
                else
                {
                    $item
                }
            }
        }
	}
	
	End 
	{
    }
}

function Get-NozbeProject()
{
    <#
        .Synopsis
            Gets projects from nozbe
        .Description
            using Nozbe API
        .Parameter Name
            [string] Name filter in wildcard form
        .Parameter Id
            [string] Id filter in wildcard form
        .Outputs
            [object[]] array of projects
        .Example
            Get-NozbeProject *task*
        .Example
            Get-NozbeProject -id 123456789
    #>

    [CmdletBinding(DefaultParametersetName="ByName")]
    Param(
		[parameter(position=0,ParameterSetName="ByName")][String]$Name,
        [parameter(position=0,ParameterSetName="ById")][String]$Id
	)
    
    $allItems = Get-Url "https://webapp.nozbe.com/api/projects/key-$(Get-APIKey)" | ConvertFrom-Json
    $allItems | % {  $_ | Add-Member -MemberType NoteProperty -Name ItemType -Value "Project" -TypeName string | Out-Null } 
    $allItems = $allItems | ConvertTo-Json | ConvertFrom-Json
    switch ($PsCmdlet.ParameterSetName) 
    { 
        "ByName" { 
            return $allItems | Filter-ByProperty -property "name" -value $Name
        }
        "ById" { 
            return $allItems | Filter-ByProperty -property "id" -value $Id
        }
    }
}

function Get-NozbeContext()
{
    <#
        .Synopsis
            Gets contexts from nozbe
        .Description
            using Nozbe API
        .Parameter Name
            [string] Name filter in wildcard form
        .Parameter Id
            [string] Id filter in wildcard form
        .Outputs
            [object[]] array of projects
        .Example
            Get-NozbeContext *task*
        .Example
            Get-NozbeContext -id 123456789
    #>

    [CmdletBinding(DefaultParametersetName="ByName")]
    Param(
		[parameter(position=0,ParameterSetName="ByName")][String]$Name,
        [parameter(position=0,ParameterSetName="ById")][String]$Id
	)
    
    $allItems = Get-Url "https://webapp.nozbe.com/api/contexts/key-$(Get-APIKey)" | ConvertFrom-Json
    $allItems | % {  $_ | Add-Member -MemberType NoteProperty -Name ItemType -Value "Context" -TypeName string | Out-Null } 
    $allItems = $allItems | ConvertTo-Json | ConvertFrom-Json
    switch ($PsCmdlet.ParameterSetName) 
    { 
        "ByName" { 
            return $allItems | Filter-ByProperty -property "name" -value $Name
        }
        "ById" { 
            return $allItems | Filter-ByProperty -property "id" -value $Id
        }
    }
}

function Get-NozbeAction()
{
    <#
        .Synopsis
            Gets actions from nozbe
        .Description
            it is possible to Pipe Projects or Contexts to filter tasks accordingly
        .Parameter Name
            [string] Name filter in wildcard form
        .Parameter Id
            [string] Id filter in wildcard form
        .Parameter NextAction
            [switch] if this switch is defined, pipe is ignored and it will return all actions which are
            in NextAction group
        .Parameter ShowDone
            [switch] Indicates to return completed tasks
        .Outputs
            [object[]] array of actions
        .Example
            Get-NozbeAction -NextAction
        .Example
            $tasks = Get-NozbeProject | Get-NozbeAction -ShowDone
    #>

    [CmdletBinding(DefaultParametersetName="ByName")]
    Param(
        [parameter(valuefrompipeline=$true)][object[]]$FilterFor,
		[parameter(position=0,ParameterSetName="ByName")][String]$Name,
        [parameter(position=0,ParameterSetName="ById")][String]$Id,
        [switch]$NextAction = $false,
        [switch]$ShowDone = $false
	)

    Begin 
	{
        if ($ShowDone)
        {
            $showdoneString = "/showdone-1"
        }
        else
        {
            $showdoneString = ""
        }

         function ConvertTo-ActionItem()
        {
            param(
                [parameter(valuefrompipeline=$true)]$items
            )

            $items | ? { $_ } | % { $_ | Add-Member -MemberType NoteProperty -Name ItemType -Value "Action" -TypeName string | Out-Null } 
            $items = $items | ConvertTo-Json | ConvertFrom-Json
            return $items
        }

        $allItems = @()
        if ($NextAction)
        {
            $allItems = Get-Url "https://webapp.nozbe.com/api/actions/what-next/key-$(Get-APIKey)" | ConvertFrom-Json | ConvertTo-ActionItem
        }
	}
	
	Process 
	{
        if (-not ($NextAction))
        {
            if ($_)
            {
                foreach ($filterForItem in $_)
                {
                    if ($filterForItem.ItemType -eq "Project")
                    {
                        $items = Get-Url "https://webapp.nozbe.com/api/actions/what-project/id-$($filterForItem.id)$($showdoneString)/key-$(Get-APIKey)" | ConvertFrom-Json | ConvertTo-ActionItem
                        foreach ($item in $items)
                        {
                            $allItems += $item
                        }
                    }
                    elseif ($filterForItem.ItemType -eq "Context")
                    {
                        $items = Get-Url "https://webapp.nozbe.com/api/actions/what-context/id-$($filterForItem.id)$($showdoneString)/key-$(Get-APIKey)" | ConvertFrom-Json | ConvertTo-ActionItem
                        foreach ($item in $items)
                        {
                            $allItems += $item
                        }
                    }
                }
            }
        }
	}
	
	End 
	{
        switch ($PsCmdlet.ParameterSetName) 
        { 
            "ByName" { 
                return $allItems | Filter-ByProperty -property "name" -value $Name
            }
            "ById" { 
                return $allItems | Filter-ByProperty -property "id" -value $Id
            }
        }
    }
}

function Complete-NozbeAction()
{
    <#
        .Synopsis
            Marks all tasks piped to this function as resolved
        .Outputs
            None
        .Example
            Get-NozbeAction -NextAction | Complete-NozbeAction
    #>

    Param(
        [parameter(valuefrompipeline=$true)][object[]]$Items,
        [switch]$WhatIf = $false
	)

    Begin 
	{
        $allItems = @()
	}
	
	Process 
	{
        if ($_)
        {
            foreach ($item in $_)
            {
                if ($item.ItemType -eq "Action")
                {
                    $allItems += $item.Id
                }
            }
        }
	}
	
	End 
	{
        $ids = [string]::Join(';', $allItems)
        if ($WhatIf)
        {
            Write-Host "Would get to URL: `"https://webapp.nozbe.com/api/check/ids-$ids/key-$(Get-APIKey)`""
        }
        else
        {
            $response = Get-Url "https://webapp.nozbe.com/api/check/ids-$ids/key-$(Get-APIKey)" | ConvertFrom-Json
            if ($response.response -ne "ok")
            {
                throw "$($response.response)"
            }
        }
    }
}

function New-NozbeAction()
{
    <#
        .Synopsis
            Creates new action
        .Parameter Name
            [string] Name of the action
        .Parameter Project
            Project object - must have ItemType="Project"
        .Parameter Time
            [int] time in seconds how much the task takes
        .Parameter Context
            Context object - must have ItemType="Context"
        .Outputs
            None
        .Example
            New-NozbeAction -Name "test action" -Project (Get-NozbeProject -Id 123456)
    #>

    Param(
		[parameter(mandatory=$true, position=0)][String]$Name,
        [parameter(mandatory=$true, position=1)]$Project,
        [parameter(position=2)][int]$Time,
        $Context,
        [switch]$Next = $false,
        [switch]$WhatIf = $false
	)

    if ($Project.ItemType -eq "Project")
    {
        $projectId = $Project.id
    }
    else
    {
        throw "Unknown project: $Project"
    }

    if ($Context.ItemType -eq "Context")
    {
        $contextId = $Context.id
        $contextStr = "/context_id-$contextId"
    }

    if ($Time)
    {
        $timeStr = "/time-$Time"
    }

    if ($Next)
    {
        $nextStr = "/next-true"
    }

    $url = "https://webapp.nozbe.com/api/newaction/name-$Name/project_id-$projectId$($contextStr)$($timeStr)$($nextStr)/key-$(Get-APIKey)"
    
    if ($WhatIf)
    {
        Write-Host "Would get to URL: `"$url`""
    }
    else
    {
        $response = Get-Url "$url" | ConvertFrom-Json
        return $response.response;
    }
}

Export-ModuleMember -Function Get-NozbeProject,Get-NozbeContext,Get-NozbeAction,Complete-NozbeAction,New-NozbeAction

function Get-APIKey {
    $apikey = [Environment]::GetEnvironmentVariable("NozbeAPIKey", "User");
    if ($apikey)
    {
        $key = Set-Key "AGoodKeyThatNoOneElseWillKnow" 
        return Get-EncryptedData -data $apikey -key $key
    }
    else
    {
        throw "API Key is not provided"
    }
}

if (-not ([Environment]::GetEnvironmentVariable("NozbeAPIKey", "User")))
{
    Write-Host "Please provide your APIKey to Nozbe server" -ForegroundColor Yellow
    Write-Host "!!WARNING!!: APIKey will be saved LOCALLY in USER environment variable in ENCRYPTED form" -ForegroundColor Red
    Write-Host "press any key to continue" -ForegroundColor Yellow
    
    $apikey = Read-Host "Write Nozbe API key" -AsSecureString
    if ($apikey)
    {
        [string]$stringValue = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($apikey)); 

        $key = Set-Key "AGoodKeyThatNoOneElseWillKnow"
        $encryptedPassword = Set-EncryptedData -key $key -plainText $stringValue

        $value = "$encryptedPassword"

        Write-Host "Creating following environment variable: NozbeAPIKey=$value" -ForegroundColor Green
        [Environment]::SetEnvironmentVariable("NozbeAPIKey", "$value", "User")
    }
}