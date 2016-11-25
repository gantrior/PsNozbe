# Project Description
PsNozbe is set of Powershell cmdlets to work with [Nozbe](https://nozbe.com) Projects/Contexts/Actions. As long as powershell is heavily supported by Windows and many other tools, it provides cool integration potential. And of course it is very helpful for geeks which uses shell on daily basis :)

After installation it asks you to provide your Nozbe API key and saves it encrypted into environment variable

# Usage Examples

Getting projects:
```
 # get all projects
Get-NozbeProject

Get-NozbeProject -Name myproj*
Get-NozbeProject -id 123456789
```

Getting contexts:
```
# get all contexts
Get-NozbeContext

Get-NozbeContext -Name myproj*
Get-NozbeContext -id 123456789
```

Getting actions:
```
# get all "Next" actions
Get-NozbeAction -NextAction

# get all actions within the project
Get-NozbeProject -Name myproj* | Get-NozbeAction

# get all actions within the context
Get-NozbeContext -Name home | Get-NozbeAction

# get all actions including completed ones
Get-NozbeProject | Get-NozbeAction -ShowDone
```

Completing actions:
```
# complete first action in Next
Get-NozbeAction -NextAction | Select -First 1 | Complete-NozbeAction
```

Creating actions:
```
# new action within the project 
New-NozbeAction -Name "Test action" -Project (Get-NozbeProject -id 123456789)
```