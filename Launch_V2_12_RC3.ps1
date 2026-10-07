#Requires -Version 5.1
param([switch]$RequestAdmin)
$ErrorActionPreference='Stop'
$log=Join-Path $PSScriptRoot 'Launcher_Error.log'
try{
    $engine=Join-Path $PSScriptRoot 'Network_Diagnostic_V2_12_RC3.ps1'
    $required=@('Network_Diagnostic_V2_12_RC3.ps1','Monitor_Config.psd1','lib\AddressPolicy.ps1','lib\WebStatus.ps1','lib\Time.ps1','lib\Core.ps1','lib\Scheduler.ps1','lib\Continuity.ps1','lib\Probes.ps1','lib\Presentation.ps1','lib\Runtime.ps1','lib\Storage.ps1','lib\Notifications.ps1','lib\WindowsForensics.ps1','lib\SelfTest.ps1','lib\Deployment.ps1')
    foreach($relative in $required){
        $path=Join-Path $PSScriptRoot $relative
        if(-not (Test-Path -LiteralPath $path)){throw ('Missing file: '+$relative+'. Extract the complete ZIP first.')}
        $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        if($errors.Count){throw (($errors | ForEach-Object{'Line '+$_.Extent.StartLineNumber+': '+$_.Message}) -join "`r`n")}
    }
    $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $conhost=Join-Path $env:SystemRoot 'System32\conhost.exe'
    # Calling the engine as a child script keeps its explicit exit code from
    # closing the interactive host before the user can read a fatal error.
    $command="& '"+$engine.Replace("'","''")+"'"
    $args='-- "'+$exe+'" -NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -Command "'+$command+'"'
    if($RequestAdmin){$process=Start-Process -FilePath $conhost -Verb RunAs -ArgumentList $args -PassThru -ErrorAction Stop}else{$process=Start-Process -FilePath $conhost -ArgumentList $args -PassThru -ErrorAction Stop}
    Start-Sleep -Milliseconds 750
    if($process.HasExited){throw 'Classic console host exited immediately. Run this launcher from an interactive Windows desktop; startup did not remain open.'}
}catch{
    $failure=$_;$identity=$null;try{$identity=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'Monitor_Config.psd1')}catch{}
    $sensor=if($identity -and $identity.SENSOR_NAME){$identity.SENSOR_NAME}else{$env:COMPUTERNAME};$role=if($identity){$identity.SENSOR_ROLE}else{'CONFIG_NOT_LOADED'}
    $message='UTC='+[datetime]::UtcNow.ToString('o')+' Local='+[datetime]::Now.ToString('o')+' Sensor='+$sensor+' Role='+$role+"`r`n"+($failure | Format-List * -Force | Out-String)
    try{[IO.File]::AppendAllText($log,$message)}catch{[Console]::Error.WriteLine('Launcher log unavailable: '+$_.Exception.Message)}
    Write-Host 'NETWORK MONITOR STARTUP ERROR' -ForegroundColor Red;Write-Host $failure.Exception.Message -ForegroundColor Red
    Write-Host ('Launcher error log: '+$log) -ForegroundColor Yellow
    [void](Read-Host 'Press ENTER to close');exit 1
}
