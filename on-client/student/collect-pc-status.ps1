#Requires -Version 5.1
<#
  KESHEV 학생 PC 조회 도구 0.1.0
  일반 권한의 로컬 읽기만 수행합니다. 설정 변경, 관리자 승격, 원격 조회,
  네트워크 전송, 공격 시험, 자격 파일 조회를 하지 않습니다.
  결과는 프로젝트 밖 LocalAppData\KESHEV\pc-status의 새 JSON 파일입니다.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Get-CheckedAt { return [DateTimeOffset]::UtcNow.ToString('o') }

function Get-SafeQueryError($Record) {
    $code = 'QUERY_FAILED'
    if ($Record.Exception -is [UnauthorizedAccessException] -or
        $Record.Exception -is [System.Security.SecurityException] -or
        $Record.Exception.HResult -eq -2147024891 -or
        [string]$Record.CategoryInfo.Category -match 'PermissionDenied|SecurityError' -or
        [string]$Record.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess|0x80070005') {
        $code = 'ACCESS_DENIED'
    } elseif ($Record.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        $code = 'COMMAND_UNAVAILABLE'
    } elseif ([string]$Record.Exception.Message -eq 'KESHEV_VALUE_UNAVAILABLE') {
        $code = 'VALUE_UNAVAILABLE'
    }
    $messages = @{
        ACCESS_DENIED = '일반 권한으로 읽을 수 없습니다. 관리자 권한으로 전환하지 않고 확인 불가로 남깁니다.'
        COMMAND_UNAVAILABLE = '이 Windows 환경에서 필요한 조회 명령을 찾지 못했습니다.'
        VALUE_UNAVAILABLE = 'Windows가 유효한 측정값을 반환하지 않았습니다.'
        QUERY_FAILED = '로컬 조회에 실패했습니다. 일반 PowerShell에서 다시 수집하고, 계속 실패하면 확인 불가로 남기세요.'
    }
    return [ordered]@{ code = $code; message = $messages[$code] }
}

function Read-PcResource([string]$Unit, [ScriptBlock]$Query) {
    try {
        $value = & $Query
        return [ordered]@{ status = 'ok'; checkedAt = (Get-CheckedAt); unit = $Unit; data = $value }
    } catch {
        return [ordered]@{ status = 'error'; checkedAt = (Get-CheckedAt); unit = $Unit; error = (Get-SafeQueryError $_) }
    }
}

function Read-WindowsLog([string]$Name, [DateTime]$Start, [DateTime]$End) {
    try {
        # 5001번째 기록으로 상한 초과를 확인하고 최대 5000건만 집계합니다.
        # 원문 메시지·사용자 이름·이벤트 본문은 출력하지 않습니다.
        # 날짜를 로캘 문자열로 다시 해석하지 않도록 UTC XPath를 직접 전달합니다.
        $keshevFromUtc = $Start.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
        $keshevToUtc = $End.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
        $keshevXPath = "*[System[(Level=2 or Level=3) and TimeCreated[@SystemTime >= '$keshevFromUtc' and @SystemTime <= '$keshevToUtc']]]"
        $rows = @(Get-WinEvent -LogName $Name -FilterXPath $keshevXPath -MaxEvents 5001 -ErrorAction Stop)
        $limited = $rows.Count -gt 5000
        $counted = @($rows | Select-Object -First 5000)
        $warnings = @($counted | Where-Object { $_.Level -eq 3 }).Count
        $errors = @($counted | Where-Object { $_.Level -eq 2 }).Count
        return [ordered]@{
            logName = $Name; status = $(if ($limited) { 'partial' } else { 'ok' })
            checkedAt = (Get-CheckedAt); warningCount = $warnings; errorCount = $errors
            truncated = $limited; countedLimit = 5000
        }
    } catch {
        if ([string]$_.FullyQualifiedErrorId -match '^NoMatchingEventsFound(?:,|$)') {
            return [ordered]@{
                logName = $Name; status = 'ok'; checkedAt = (Get-CheckedAt)
                warningCount = 0; errorCount = 0; truncated = $false; countedLimit = 5000
            }
        }
        return [ordered]@{ logName = $Name; status = 'error'; checkedAt = (Get-CheckedAt); error = (Get-SafeQueryError $_) }
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw '이 수집 도구는 Windows PowerShell 5.1 이상에서 실행하세요.'
}
$keshevIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $keshevPrincipal = [Security.Principal.WindowsPrincipal]::new($keshevIdentity)
    if ($keshevPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '관리자 창에서는 수집하지 않습니다. 일반 PowerShell 창을 열어 실행하세요.'
    }
} finally { $keshevIdentity.Dispose() }

$keshevStartedAt = Get-CheckedAt
Write-Host '일반 권한으로 PC 정보를 읽는 중입니다. 설정은 변경하지 않습니다.'
$keshevHasher = [Security.Cryptography.SHA256]::Create()
try {
    # 동일 PC의 표본끼리만 비교하기 위한 이름 해시이며 인증 수단이 아닙니다.
    $keshevComputerId = ([BitConverter]::ToString($keshevHasher.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes([Environment]::MachineName.ToUpperInvariant())
    ))).Replace('-', '').ToLowerInvariant()
} finally { $keshevHasher.Dispose() }

$keshevCpu = Read-PcResource '%' {
    $processors = @(Get-CimInstance -ClassName Win32_Processor -OperationTimeoutSec 10 -ErrorAction Stop)
    if ($processors.Count -eq 0) { throw 'KESHEV_VALUE_UNAVAILABLE' }
    $loads = @()
    foreach ($processor in $processors) {
        if ($null -eq $processor.LoadPercentage -or $processor.LoadPercentage -lt 0 -or $processor.LoadPercentage -gt 100) {
            throw 'KESHEV_VALUE_UNAVAILABLE'
        }
        $loads += [double]$processor.LoadPercentage
    }
    return [ordered]@{ usagePercent = [Math]::Round(($loads | Measure-Object -Average).Average, 1) }
}

$keshevMemory = Read-PcResource 'GiB,%' {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 10 -ErrorAction Stop
    if ($null -eq $os.TotalVisibleMemorySize -or $null -eq $os.FreePhysicalMemory -or
        $os.TotalVisibleMemorySize -le 0 -or $os.FreePhysicalMemory -gt $os.TotalVisibleMemorySize) {
        throw 'KESHEV_VALUE_UNAVAILABLE'
    }
    $total = [double]$os.TotalVisibleMemorySize * 1024
    $used = ([double]$os.TotalVisibleMemorySize - [double]$os.FreePhysicalMemory) * 1024
    return [ordered]@{
        usedGiB = [Math]::Round($used / 1GB, 3); totalGiB = [Math]::Round($total / 1GB, 3)
        usagePercent = [Math]::Round($used / $total * 100, 1)
    }
}

$keshevDisks = Read-PcResource 'GiB,%' {
    $items = @()
    foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 10 -ErrorAction Stop | Sort-Object DeviceID)) {
        if ([string]$disk.DeviceID -notmatch '^[A-Za-z]:$') { throw 'KESHEV_VALUE_UNAVAILABLE' }
        if ($null -eq $disk.Size -or $null -eq $disk.FreeSpace -or $disk.Size -le 0 -or $disk.FreeSpace -gt $disk.Size) {
            $items += [ordered]@{ id = [string]$disk.DeviceID; status = 'error'; error = @{
                code = 'VALUE_UNAVAILABLE'; message = '이 드라이브의 용량을 읽을 수 없습니다.'
            } }
        } else {
            $items += [ordered]@{
                id = [string]$disk.DeviceID; status = 'ok'
                freeGiB = [Math]::Round([double]$disk.FreeSpace / 1GB, 3)
                totalGiB = [Math]::Round([double]$disk.Size / 1GB, 3)
                freePercent = [Math]::Round([double]$disk.FreeSpace / [double]$disk.Size * 100, 1)
            }
        }
    }
    return [ordered]@{ systemDrive = [IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\'); items = @($items) }
}

$keshevNetwork = Read-PcResource '주소,상태' {
    $items = @()
    $configurations = @(Get-NetIPConfiguration -ErrorAction Stop)
    foreach ($configuration in @($configurations | Select-Object -First 32)) {
        $items += [ordered]@{
            label = [string]$configuration.InterfaceAlias
            ipv4 = @($configuration.IPv4Address | ForEach-Object { [string]$_.IPAddress })
            ipv6 = @($configuration.IPv6Address | ForEach-Object { [string]$_.IPAddress })
            gateway = @(@($configuration.IPv4DefaultGateway) + @($configuration.IPv6DefaultGateway) |
                Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.NextHop })
            dns = @($configuration.DNSServer | Where-Object { $null -ne $_ } |
                ForEach-Object { $_.ServerAddresses } | ForEach-Object { [string]$_ })
        }
    }
    return [ordered]@{ items = @($items); truncated = $configurations.Count -gt 32 }
}

$keshevFirewall = Read-PcResource '상태' {
    $items = @()
    foreach ($profile in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        $items += [ordered]@{
            name = [string]$profile.Name; enabled = [string]$profile.Enabled
            defaultInboundAction = [string]$profile.DefaultInboundAction
            defaultOutboundAction = [string]$profile.DefaultOutboundAction
        }
    }
    return [ordered]@{ items = @($items) }
}

$keshevWindowEnd = [DateTime]::UtcNow
$keshevWindowStart = $keshevWindowEnd.AddHours(-24)
$keshevLogRows = @(
    (Read-WindowsLog 'System' $keshevWindowStart $keshevWindowEnd)
    (Read-WindowsLog 'Application' $keshevWindowStart $keshevWindowEnd)
)
$keshevEvents = [ordered]@{
    status = 'ok'; checkedAt = (Get-CheckedAt); unit = '건'
    data = [ordered]@{
        windowStart = ([DateTimeOffset]$keshevWindowStart).ToString('o')
        windowEnd = ([DateTimeOffset]$keshevWindowEnd).ToString('o'); logs = @($keshevLogRows)
    }
}
if (@($keshevLogRows | Where-Object { $_.status -eq 'ok' }).Count -ne 2) { $keshevEvents.status = 'partial' }
if (@($keshevLogRows | Where-Object { $_.status -eq 'error' }).Count -eq 2) { $keshevEvents.status = 'error' }

$keshevOutput = [ordered]@{
    schema = 'keshev.pc-status.v1'
    source = [ordered]@{ mode = 'measured'; kind = 'windows-powershell'; collectorVersion = '0.1.0'; computerId = $keshevComputerId }
    startedAt = $keshevStartedAt; finishedAt = (Get-CheckedAt)
    cpu = $keshevCpu; memory = $keshevMemory; disks = $keshevDisks
    network = $keshevNetwork; firewall = $keshevFirewall; events = $keshevEvents
}
$keshevDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'KESHEV\pc-status'
[IO.Directory]::CreateDirectory($keshevDirectory) | Out-Null
$keshevName = 'pc-status-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json'
$keshevPath = Join-Path $keshevDirectory $keshevName
$keshevJson = $keshevOutput | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($keshevPath, $keshevJson, [Text.UTF8Encoding]::new($false))
Write-Host 'PC 조회가 끝났습니다. 항목별 실패 여부는 앱에서 확인하세요.'
Write-Host ('수집 파일: ' + $keshevPath)
Write-Host '보호 현황의 학생 대시보드에서 다시 조회를 누르고 이 파일을 선택하세요.'
Write-Host 'SDP 연결·공격 탐지·보안 조치를 수행한 결과가 아닙니다.'
