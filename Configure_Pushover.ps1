#Requires -Version 5.1
param([switch]$TestOnly)
$ErrorActionPreference='Stop'
try{
    . (Join-Path $PSScriptRoot 'lib\Notifications.ps1')
    $cfg=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'Monitor_Config.psd1')
    $path=Get-PushoverSecretPath $cfg.PushoverSecretPath
    Assert-PushoverSecretLocation $path $cfg.RootDir $PSScriptRoot
    if(-not $TestOnly){
        Write-Host 'Install Pushover on your phone and sign in to https://pushover.net.'
        Write-Host 'Register an application named NetDiag at https://pushover.net/apps/build.'
        Write-Host 'Enter its API token and your dashboard User Key below. Input is hidden.'
        Write-Host 'Keys are protected for this Windows user/machine and excluded from run exports.'
        $token=Read-Host 'Application API Token (30 characters)' -AsSecureString
        $userKey=Read-Host 'Your User Key (30 characters)' -AsSecureString
        $secrets=[pscustomobject]@{SchemaVersion=1;AppToken=$token;UserKey=$userKey}
        if(-not (Test-PushoverKeys $secrets)){throw 'Both keys must be exactly 30 letters/digits. No keys were printed or saved.'}
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        $tmp=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        try{$secrets | Export-Clixml -LiteralPath $tmp -Encoding UTF8;if([IO.File]::Exists($path)){[IO.File]::Replace($tmp,$path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$path)}}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
        Write-Host ('Protected keys saved: '+$path) -ForegroundColor Green
    }else{$secrets=Import-Clixml -LiteralPath $path}
    if(-not (Test-PushoverKeys $secrets)){throw 'Protected keys unavailable. Run SETUP_PUSHOVER.bat under this Windows account.'}
    $now=[datetime]::UtcNow;$item=[pscustomobject]@{Title='NetDiag SETUP TEST';Message='This is a setup test, not a network incident. Sensor='+$env:COMPUTERNAME+' UTC='+$now.ToString('o');Priority=0;CreatedUTC=$now.ToString('o')}
    $result=Invoke-PushoverDelivery $item $secrets $cfg.PushoverDevice $cfg.AlertRequestTimeoutSec
    if(-not $result.Succeeded){throw ('Pushover did not accept the test ('+$result.FailureCode+'). Check Internet access and keys. Saved keys remain available for retry.')}
    Write-Host 'Pushover accepted the test. Verify that it appeared on your phone before relying on alerts.' -ForegroundColor Green
    Write-Host 'Restart the monitor after setup. EnablePushover must be true in Monitor_Config.psd1.'
}catch{Write-Host ('Pushover setup/test failed: '+$_.Exception.Message) -ForegroundColor Red;exit 1}
