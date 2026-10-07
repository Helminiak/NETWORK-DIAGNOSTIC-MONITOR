#Requires -Version 5.1
[CmdletBinding()]
param([string]$ConfigPath='',[switch]$NoBrowser)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Runtime.ps1')
try{
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Background launch requires Windows PowerShell 5.1.'}
    if(-not $ConfigPath){$ConfigPath=Join-Path $PSScriptRoot 'Monitor_Config.psd1'}
    $ConfigPath=[IO.Path]::GetFullPath($ConfigPath);$cfg=Read-MonitorConfig $ConfigPath
    if(-not $cfg.EnableWebStatus -and -not $NoBrowser){throw 'EnableWebStatus must be true to open the browser screen.'}
    $url='http://127.0.0.1:'+$cfg.WebStatusPort+'/'
    $control=Join-Path $cfg.RootDir ('Supervisor_'+$cfg.SENSOR_NAME)
    [void][IO.Directory]::CreateDirectory($control)
    if(([IO.File]::GetAttributes($control) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Supervisor control cannot be a reparse point.'}
    $alreadyRunning=$false
    try{$lock=[IO.File]::Open((Join-Path $control '.supervisor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{$alreadyRunning=$true}
    if(-not $alreadyRunning){
        try{$marker=Join-Path $control 'StopSupervisor.txt';if([IO.File]::Exists($marker)){[IO.File]::Delete($marker)}}finally{$lock.Dispose()}
        $exe=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $command="& '"+(Join-Path $PSScriptRoot 'Supervise_Monitor.ps1').Replace("'","''")+"' -ConfigPath '"+$ConfigPath.Replace("'","''")+"'"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $info=[Diagnostics.ProcessStartInfo]::new($exe,('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded))
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $process=[Diagnostics.Process]::new();$process.StartInfo=$info;[void]$process.Start();$process.Dispose()
    }
    if(-not $NoBrowser){Start-Process -FilePath $url}
}catch{
    $detail='UTC='+[datetime]::UtcNow.ToString('o')+' '+$_.Exception.Message
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Background_Launch_Error.log'),$detail)
    Write-Error $detail;exit 1
}
