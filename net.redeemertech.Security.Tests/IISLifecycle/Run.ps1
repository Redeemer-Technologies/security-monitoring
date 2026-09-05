param([int]$Port = 18769)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$run = Join-Path $repo ('TestResults/IISLifecycle-' + [Guid]::NewGuid().ToString('N'))
$site = Join-Path $run 'site'
$bin = Join-Path $site 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
# Copy the built plugin dependencies, but not tests or site configuration.
Copy-Item -Path (Join-Path $repo 'net.redeemertech.Security/bin/Debug/*.dll') -Destination $bin
$csc = 'C:/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/Roslyn/csc.exe'
& $csc /nologo /target:library "/out:$bin/net.redeemertech.Security.Tests.dll" "/reference:$bin/net.redeemertech.Security.dll" /reference:System.Web.dll /reference:System.Web.Extensions.dll (Join-Path $PSScriptRoot 'Harness.cs')
if ($LASTEXITCODE -ne 0) { throw 'Harness compilation failed.' }
@'
<configuration><appSettings><add key="owin:AutomaticAppStartup" value="false"/></appSettings>
  <system.web><compilation targetFramework="4.7.2"/><httpRuntime targetFramework="4.7.2"/></system.web>
  <system.webServer>
    <modules><add name="LifecycleHarness" type="LifecycleHarness, net.redeemertech.Security.Tests"/></modules>
    <handlers><add name="Probe" path="probe.ashx" verb="*" type="ProbeHandler, net.redeemertech.Security.Tests" resourceType="Unspecified"/></handlers>
  </system.webServer>
</configuration>
'@ | Set-Content (Join-Path $site 'web.config')
[xml]$config = Get-Content 'C:/Program Files/IIS Express/config/templates/PersonalWebServer/applicationhost.config'
$config.configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath = $site
$config.configuration.'system.applicationHost'.sites.site.bindings.binding.bindingInformation = ":${Port}:localhost"
foreach ($pool in $config.configuration.'system.applicationHost'.applicationPools.add) { $pool.RemoveAttribute('CLRConfigFile') }
$configPath = Join-Path $run 'applicationhost.config'
$config.Save($configPath)
$process = Start-Process 'C:/Program Files/IIS Express/iisexpress.exe' -ArgumentList @("/config:`"$configPath`"", '/site:WebSite1', '/systray:false') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $run 'iis.log') -RedirectStandardError (Join-Path $run 'iis-error.log')
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { $null = Invoke-WebRequest "http://localhost:$Port/probe.ashx?mode=warmup" -UseBasicParsing; $ready = $true; break }
        catch { $_ | Out-String | Set-Content (Join-Path $run 'request-error.txt'); if ($process.HasExited) { throw "IIS exited; see $run" }; Start-Sleep -Milliseconds 300 }
    }
    if (!$ready) { throw "IIS did not become ready; see $run" }
    $modes = @('buffered','flush','streaming','early','end','emptyflush','empty')
    foreach ($mode in $modes) {
        $response = Invoke-WebRequest "http://localhost:$Port/probe.ashx?mode=$mode" -UseBasicParsing
        $expected = if ($mode -in @('early','end')) { 17 } elseif ($mode -eq 'empty') { 0 } else { 46 }
        if ($response.RawContentLength -ne $expected) { throw "$mode delivered $($response.RawContentLength), expected $expected" }
    }
    Start-Sleep -Milliseconds 300
    $events = Get-Content (Join-Path $site 'events.jsonl') | ForEach-Object { $_ | ConvertFrom-Json }
    foreach ($mode in $modes) {
        $expected = if ($mode -in @('early','end')) { 17 } elseif ($mode -eq 'empty') { 0 } else { 46 }
        $final = $events | Where-Object { $_.mode -eq $mode } | Select-Object -Last 1
        if (!$final.available -or !$final.processed -or $final.bytes -ne $expected) { throw "$mode final evaluation incorrect: $($final | ConvertTo-Json -Compress); see $run" }
        $matches = @($events | Where-Object { $_.mode -eq $mode -and $_.event -eq 'RuleMatched' })
        if ($matches.Count -ne 1) { throw "$mode matched $($matches.Count) times; expected exactly once; see $run" }
        Write-Output "$mode : delivered and measured $expected bytes; byte rule matched exactly once."
    }
    Write-Output "Lifecycle event evidence: $run"
}
finally { if (!$process.HasExited) { Stop-Process -Id $process.Id } }


