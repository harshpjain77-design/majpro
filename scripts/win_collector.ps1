<#
.SYNOPSIS
    ThreadGrid Native Windows Event Log Collector (PowerShell)
    Zero-dependency collector compatible with Windows 7, 8, 10, 11, and Windows Server 2008R2/2012/2016/2019/2022.

.DESCRIPTION
    Monitors the Windows Security log for authentications (4624, 4625), privilege escalation (4672),
    and user account modifications (4720, 4726, 4740), normalizes them to ThreadGrid schema,
    and streams them to the Central Ingestion API via HTTP.

.PARAMETER ApiUrl
    ThreadGrid Ingestion API URL (e.g. http://192.168.80.1:8000/api/v1/ingest)

.PARAMETER ApiKey
    Collector API key.

.PARAMETER Channel
    Windows Event Log channel (default: 'Security').

.PARAMETER IntervalSeconds
    Polling interval in seconds (default: 5).

.PARAMETER TestEvent
    If specified, generates and ships a synthetic test event immediately to verify connectivity.
#>

param(
    [string]$ApiUrl = "http://192.168.80.1:8000/api/v1/ingest",
    [string]$ApiKey = "test-collector-api-key-replace-in-production",
    [string]$Channel = "Security",
    [int]$IntervalSeconds = 5,
    [string]$HostOverride = "",
    [switch]$TestEvent,
    [switch]$RunOnce
)

$ErrorActionPreference = "Continue"

# Determine Hostname
$HostName = if ($HostOverride -ne "") { $HostOverride } else { $env:COMPUTERNAME }
if ([string]::IsNullOrEmpty($HostName)) { $HostName = "WINDOWS-HOST" }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ThreatGrid SOC - Native Windows Collector              " -ForegroundColor Cyan
Write-Host "   Host: $HostName | Target SIEM: $ApiUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Universal HTTP Shipper (Compatible with PowerShell 2.0 to 7.0+)
function Send-ThreadGridBatch {
    param(
        [string]$Url,
        [string]$Key,
        [string]$JsonBody
    )

    try {
        $endpoint = $Url.TrimEnd('/')
        # Append /batch if needed
        if (-not $endpoint.EndsWith("/batch") -and -not $endpoint.EndsWith("/ingest")) {
            $endpoint = "$endpoint/api/v1/ingest"
        }

        # Check for Invoke-RestMethod (PowerShell 3.0+)
        if (Get-Command Invoke-RestMethod -ErrorAction SilentlyContinue) {
            $headers = @{
                "Content-Type"  = "application/json"
                "X-API-Key"     = $Key
                "Authorization" = "Bearer $Key"
            }
            $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $JsonBody -TimeoutSec 10
            return $true
        } else {
            # Fallback to .NET WebClient (PowerShell 2.0 / Windows 7 base)
            $client = New-Object System.Net.WebClient
            $client.Headers.Add("Content-Type", "application/json")
            $client.Headers.Add("X-API-Key", $Key)
            $client.Headers.Add("Authorization", "Bearer $Key")
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
            $respBytes = $client.UploadData($endpoint, "POST", $bytes)
            $client.Dispose()
            return $true
        }
    } catch {
        Write-Host "[ERROR] Failed to ship event(s): $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Generate unique event ID
function New-EventId {
    param([string]$Computer, [string]$Time, [int]$RecordId)
    $raw = "$Computer-$Time-$RecordId"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
    $hashStr = [BitConverter]::ToString($hashBytes) -replace '-'
    return $hashStr.ToLower()
}

# If user asked for test event, ship it and exit
if ($TestEvent) {
    Write-Host "[TEST] Sending test connection event to ThreadGrid SIEM..." -ForegroundColor Yellow
    $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $testObj = @(
        @{
            schema_version    = "1.0"
            event_id          = [Guid]::NewGuid().ToString()
            timestamp         = $nowIso
            observed_at       = $nowIso
            source_host       = $HostName
            source_type       = "windows_security"
            event_type        = "authentication_success"
            username          = $env:USERNAME
            source_ip         = "127.0.0.1"
            windows_event_id  = 4624
            severity          = "low"
            raw_event         = "Test connectivity event from $HostName ($([System.Environment]::OSVersion.VersionString))"
            collector_version = "0.1.0"
            metadata          = @{
                channel        = $Channel
                os             = [System.Environment]::OSVersion.VersionString
                collector_type = "powershell_native"
            }
        }
    )
    $json = ConvertTo-Json $testObj -Compress
    $ok = Send-ThreadGridBatch -Url $ApiUrl -Key $ApiKey -JsonBody $json
    if ($ok) {
        Write-Host "[SUCCESS] Test event received by ThreadGrid! Check Overview & Entities page." -ForegroundColor Green
    }
    exit 0
}

# Checkpoint tracking file
$checkpointFile = Join-Path $PSScriptRoot "checkpoint_$HostName.txt"
$lastRecord = 0
if (Test-Path $checkpointFile) {
    $content = Get-Content $checkpointFile -ErrorAction SilentlyContinue
    if ($content -match '^\d+$') {
        $lastRecord = [int64]$content
    }
}

# Initial policy: if checkpoint is 0, start from current newest record to prevent back-dumping thousands of old logs
if ($lastRecord -eq 0) {
    try {
        $latest = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
        if ($latest) {
            $lastRecord = $latest.RecordId
            Set-Content -Path $checkpointFile -Value $lastRecord
            Write-Host "[INIT] Initialized checkpoint at latest record: $lastRecord" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[WARN] Could not get latest record from '$Channel'. Starting from 0." -ForegroundColor Yellow
    }
}

Write-Host "[INFO] Starting collection loop on '$Channel' channel (Poll every ${IntervalSeconds}s)..." -ForegroundColor Green
Write-Host "[INFO] Press Ctrl+C to stop collector.`n" -ForegroundColor DarkGray

while ($true) {
    try {
        # Query Security events
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="$Channel">
    <Select Path="$Channel">*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4726 or EventID=4740) and EventRecordID &gt; $lastRecord]]</Select>
  </Query>
</QueryList>
"@

        $events = Get-WinEvent -FilterXml $filterXml -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events -and $events.Count -gt 0) {
            $batch = @()
            $maxSeen = $lastRecord

            # Get-WinEvent returns newest first, so reverse to chronological order
            [array]::Reverse($events)

            foreach ($evt in $events) {
                if ($evt.RecordId -gt $maxSeen) {
                    $maxSeen = $evt.RecordId
                }

                $timeIso = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $observedIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $evId = New-EventId -Computer $HostName -Time $timeIso -RecordId $evt.RecordId

                $eventIdNum = $evt.Id
                $eventType = "unknown"
                $severity = "informational"
                $username = "SYSTEM"
                $sourceIp = "127.0.0.1"

                # Parse XML payload
                try {
                    $xml = [xml]$evt.ToXml()
                    $dataDict = @{}
                    foreach ($d in $xml.Event.EventData.Data) {
                        if ($d.Name) { $dataDict[$d.Name] = $d.'#text' }
                    }

                    if ($dataDict.ContainsKey("TargetUserName") -and $dataDict["TargetUserName"]) {
                        $username = $dataDict["TargetUserName"]
                    } elseif ($dataDict.ContainsKey("SubjectUserName") -and $dataDict["SubjectUserName"]) {
                        $username = $dataDict["SubjectUserName"]
                    }

                    if ($dataDict.ContainsKey("IpAddress") -and $dataDict["IpAddress"] -ne "-" -and $dataDict["IpAddress"] -ne "") {
                        $sourceIp = $dataDict["IpAddress"]
                    }
                } catch {}

                # Map event types
                switch ($eventIdNum) {
                    4624 {
                        $eventType = "authentication_success"
                        $severity = "low"
                    }
                    4625 {
                        $eventType = "authentication_failure"
                        $severity = "medium"
                    }
                    4672 {
                        $eventType = "privilege_escalation"
                        $severity = "informational"
                    }
                    4720 {
                        $eventType = "account_created"
                        $severity = "medium"
                    }
                    4726 {
                        $eventType = "account_deleted"
                        $severity = "medium"
                    }
                    4740 {
                        $eventType = "account_lockout"
                        $severity = "high"
                    }
                }

                $normalized = @{
                    schema_version    = "1.0"
                    event_id          = $evId
                    timestamp         = $timeIso
                    observed_at       = $observedIso
                    source_host       = $HostName
                    source_type       = "windows_security"
                    event_type        = $eventType
                    username          = $username
                    source_ip         = $sourceIp
                    windows_event_id  = $eventIdNum
                    severity          = $severity
                    raw_event         = "EventID: $eventIdNum | User: $username | IP: $sourceIp on $HostName"
                    collector_version = "0.1.0"
                    metadata          = @{
                        channel        = $Channel
                        record_number  = $evt.RecordId
                        provider       = $evt.ProviderName
                        collector_type = "powershell_native"
                    }
                }

                $batch += $normalized
            }

            if ($batch.Count -gt 0) {
                $jsonPayload = ConvertTo-Json $batch -Compress
                $shipped = Send-ThreadGridBatch -Url $ApiUrl -Key $ApiKey -JsonBody $jsonPayload
                if ($shipped) {
                    Write-Host "[SHIPPED] Successfully shipped $($batch.Count) event(s) to ThreadGrid (Record: $maxSeen)" -ForegroundColor Green
                    $lastRecord = $maxSeen
                    Set-Content -Path $checkpointFile -Value $lastRecord
                }
            }
        }
    } catch {
        Write-Host "[WARN] Collection check exception: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($RunOnce) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
