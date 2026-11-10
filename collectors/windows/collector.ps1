<#
.SYNOPSIS
    Native Windows Server 2012 Real-Time Event Log Collector for AI Cyber Defense Platform.
.DESCRIPTION
    Reads real Windows Event Logs from native channels (Security/System/Application),
    normalizes them into Canonical SecurityEvent v1.0 schema, maintains a persistent checkpoint,
    and ships batches to the SIEM ingestion API over HTTP. Compatible with PowerShell 3.0+ on Windows Server 2012.
#>

[CmdletBinding()]
param (
    [string]$SiemIngestUrl = $(if ($env:SIEM_INGEST_URL) { $env:SIEM_INGEST_URL } else { "http://192.168.203.1:8000/api/v1/ingest/batch" }),
    [string]$ApiKey = $(if ($env:INGESTION_API_KEY) { $env:INGESTION_API_KEY } else { "test-collector-api-key-replace-in-production" }),
    [string]$CollectorId = $(if ($env:COLLECTOR_ID) { $env:COLLECTOR_ID } else { "windows-server-2012" }),
    [string]$Channel = "All", # "All", "Security", "System", or "Application"
    [string]$CheckpointPath = "checkpoint_windows.json",
    [int]$BatchSize = 50,
    [int]$Interval = 3,
    [int]$Lookback = 50,
    [switch]$AuthOnly,
    [switch]$Once,
    [switch]$AutoFallback = $true
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AI Cyber Defense Platform: Real-Time Windows Collector" -ForegroundColor Cyan
Write-Host " Target SIEM URL : $SiemIngestUrl" -ForegroundColor Cyan
Write-Host " Collector ID    : $CollectorId" -ForegroundColor Cyan
Write-Host " Target Channel  : $Channel" -ForegroundColor Cyan
Write-Host " Lookback        : $Lookback event(s) on initial startup" -ForegroundColor Cyan
Write-Host " Poll Interval   : $Interval second(s)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Ensure TLS 1.2 is enabled
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Cache local host IPv4 address for events without explicit network client IP
$script:LocalHostIp = $null
try {
    $script:LocalHostIp = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | Where-Object { 
        $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and 
        $_.IPAddressToString -notlike "127.*" -and 
        $_.IPAddressToString -notlike "169.254.*" 
    } | Select-Object -First 1).IPAddressToString
} catch {}
if (-not $script:LocalHostIp) { $script:LocalHostIp = "192.168.203.10" }

# 1. Channel-Aware Checkpoint Functions
function Get-LastRecordNumber {
    param ([string]$Path, [string]$Chan)
    if (Test-Path $Path) {
        try {
            $content = Get-Content -Path $Path -Raw | ConvertFrom-Json
            if ($content.channels -and $content.channels.PSObject.Properties[$Chan]) {
                return [int64]$content.channels.$Chan
            }
            if ($content.last_record_number -and ($content.channel -eq $Chan -or -not $content.channel)) {
                return [int64]$content.last_record_number
            }
        } catch {
            Write-Warning "Could not read checkpoint file: $_"
        }
    }
    return 0
}

function Set-LastRecordNumber {
    param ([string]$Path, [int64]$RecordNumber, [string]$Chan)
    $obj = @{
        channel = $Chan
        last_record_number = $RecordNumber
        updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        channels = @{}
    }
    if (Test-Path $Path) {
        try {
            $existing = Get-Content -Path $Path -Raw | ConvertFrom-Json
            if ($existing.channels) {
                foreach ($prop in $existing.channels.PSObject.Properties) {
                    $obj.channels[$prop.Name] = $prop.Value
                }
            }
        } catch {}
    }
    $obj.channels[$Chan] = $RecordNumber
    $obj | ConvertTo-Json -Depth 3 | Set-Content -Path $Path -Encoding UTF8
}

# 2. SHA-256 Event Fingerprinting
function New-EventFingerprint {
    param ([string]$Raw)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Raw)
    $hash = $sha.ComputeHash($bytes)
    $hex = -join ($hash | ForEach-Object { "{0:x2}" -f $_ })
    return "evt_$($hex.Substring(0, 32))"
}

# 3. Collection Function for a Single Channel
function Invoke-ChannelPass {
    param ([string]$Chan)

    $lastRec = Get-LastRecordNumber -Path $CheckpointPath -Chan $Chan

    # Initial Lookback
    if ($lastRec -eq 0) {
        try {
            $latestEv = Get-WinEvent -LogName $Chan -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($latestEv) {
                $lastRec = [Math]::Max(0, [int64]$latestEv.RecordId - $Lookback)
                Write-Host "[INIT] Starting '$Chan' from record $lastRec (ingesting past $Lookback events)..." -ForegroundColor Yellow
                Set-LastRecordNumber -Path $CheckpointPath -RecordNumber $lastRec -Chan $Chan
            }
        } catch {
            if ($Chan -eq "Security" -and $AutoFallback) {
                Write-Warning "Access denied to 'Security' channel without elevation. Skipping."
                return 0
            }
            Write-Warning "Cannot access '$Chan': $_"
            return 0
        }
    }

    $highestRecord = $lastRec

    # Build valid XPath without redundant nested System/ prefixes
    if ($AuthOnly -and $Chan -eq "Security") {
        $idFilter = "(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4634 or EventID=4720 or EventID=4740)"
        if ($lastRec -gt 0) {
            $xpath = "*[System[$idFilter and EventRecordID > $lastRec]]"
        } else {
            $xpath = "*[System[$idFilter]]"
        }
    } else {
        if ($lastRec -gt 0) {
            $xpath = "*[System[EventRecordID > $lastRec]]"
        } else {
            $xpath = "*"
        }
    }

    try {
        $rawEvents = Get-WinEvent -LogName $Chan -FilterXPath $xpath -MaxEvents $BatchSize -ErrorAction Stop
    } catch [System.Exception] {
        if ($_.Exception.Message -match "No events were found" -or $_.FullyQualifiedErrorId -match "NoMatchingEventsFound") {
            return 0
        }
        if ($Chan -eq "Security" -and $AutoFallback) {
            Write-Warning "Access denied on Security log. Run as Administrator to tail Security."
            return 0
        }
        Write-Warning "Error querying $Chan : $_"
        return 0
    }

    if (-not $rawEvents) { return 0 }

    $eventList = @()
    $nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    foreach ($ev in $rawEvents) {
        $recId = $ev.RecordId
        if ($recId -gt $highestRecord) { $highestRecord = $recId }

        $evXml = $ev.ToXml()
        [xml]$x = $evXml

        $evtId = $ev.Id
        $timeCreated = $ev.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $comp = if ($ev.MachineName) { $ev.MachineName } else { $env:COMPUTERNAME }
        $provider = if ($ev.ProviderName) { $ev.ProviderName } else { "" }
        $level = $ev.Level

        # Map event type and severity
        $eventType = "unknown"
        $severity = "informational"
        $user = $null
        $domain = $null
        $ip = $null

        # Parse EventData
        $dataHash = @{}
        if ($x.Event.EventData.Data) {
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name) { $dataHash[$d.Name] = $d.'#text' }
            }
        }

        if ($dataHash.ContainsKey("IpAddress") -and $dataHash["IpAddress"] -ne "-") {
            $ip = $dataHash["IpAddress"]
        } else {
            $ip = $script:LocalHostIp
        }

        switch ($evtId) {
            4624 {
                $eventType = "authentication_success"
                $severity = "low"
                $user = $dataHash["TargetUserName"]
                $domain = $dataHash["TargetDomainName"]
            }
            4625 {
                $eventType = "authentication_failure"
                $severity = "medium"
                $user = $dataHash["TargetUserName"]
                $domain = $dataHash["TargetDomainName"]
            }
            4672 {
                $eventType = "privilege_escalation"
                $severity = "informational"
                $user = $dataHash["SubjectUserName"]
                $domain = $dataHash["SubjectDomainName"]
            }
            4634 {
                $eventType = "session_logoff"
                $severity = "informational"
                $user = $dataHash["TargetUserName"]
            }
            4720 {
                $eventType = "account_created"
                $severity = "medium"
                $user = $dataHash["TargetUserName"]
            }
            4740 {
                $eventType = "account_lockout"
                $severity = "high"
                $user = $dataHash["TargetUserName"]
            }
            default {
                if ($level -eq 1 -or $evXml -match "(?i)critical|malicious|ransomware|mimikatz|unauthorized") {
                    $severity = "critical"
                    if ($eventType -eq "unknown") { $eventType = "suspicious_activity" }
                }
                elseif ($level -eq 2) { $severity = "high" }
                elseif ($level -eq 3) { $severity = "medium" }
                elseif ($level -eq 4) { $severity = "informational" }
            }
        }

        $sourceType = if ($Chan.ToLower() -eq "security") { "windows_security" } else { "windows_$($Chan.ToLower())" }

        # Deterministic event fingerprint
        $rawSeed = "$comp`:$sourceType`:$timeCreated`:$recId"
        $eventId = New-EventFingerprint -Raw $rawSeed

        $meta = @{
            channel = $Chan
            provider = $provider
            level = $level
            collector_id = $CollectorId
            record_number = $recId
        }
        if ($domain) { $meta["domain"] = $domain }

        $eventObj = @{
            schema_version = "1.0"
            event_id = $eventId
            timestamp = $timeCreated
            observed_at = $nowUtc
            source_host = $comp
            source_type = $sourceType
            event_type = $eventType
            username = $user
            source_ip = $ip
            destination_ip = $null
            windows_event_id = [int]$evtId
            severity = $severity
            raw_event = $evXml
            collector_version = "0.1.0"
            metadata = $meta
        }
        $eventList += $eventObj
    }

    if ($eventList.Count -eq 0) { return 0 }

    # Build and ship payload
    $payload = @{
        events = $eventList
        agent_id = $CollectorId
        collector_version = "0.1.0"
    }
    $jsonPayload = $payload | ConvertTo-Json -Depth 5

    $headers = @{
        "X-API-Key" = $ApiKey
        "X-Agent-ID" = $CollectorId
        "Content-Type" = "application/json"
    }

    try {
        $resp = Invoke-RestMethod -Uri $SiemIngestUrl -Method Post -Body $jsonPayload -Headers $headers -TimeoutSec 10
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [$Chan] Shipped $($eventList.Count) event(s) -> Ingested: $($resp.ingested_count), Duplicates: $($resp.duplicate_count)" -ForegroundColor Green
        
        Set-LastRecordNumber -Path $CheckpointPath -RecordNumber $highestRecord -Chan $Chan
        return $eventList.Count
    } catch {
        Write-Error "Failed to ship events to $SiemIngestUrl : $_"
        return 0
    }
}

# 4. Periodic Agent Heartbeat (Live Ping when OS is Idle)
function Invoke-HeartbeatPass {
    $nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $comp = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "WIN-SRV-2012" }
    $rawSeed = "$comp`:heartbeat`:$nowUtc"
    $hbId = New-EventFingerprint -Raw $rawSeed

    $hbEvent = @{
        schema_version = "1.0"
        event_id = $hbId
        timestamp = $nowUtc
        observed_at = $nowUtc
        source_host = $comp
        source_type = "windows_heartbeat"
        event_type = "system_heartbeat"
        username = $null
        source_ip = $script:LocalHostIp
        destination_ip = $null
        windows_event_id = $null
        severity = "informational"
        raw_event = "[HEARTBEAT] Telemetry agent active on $comp ($script:LocalHostIp). Windows Server 2012 health OK."
        collector_version = "0.1.0"
        metadata = @{
            collector_id = $CollectorId
            channel = "Heartbeat"
            status = "online"
        }
    }

    $payload = @{
        events = @($hbEvent)
        agent_id = $CollectorId
        collector_version = "0.1.0"
    }
    $jsonPayload = $payload | ConvertTo-Json -Depth 5
    $headers = @{
        "X-API-Key" = $ApiKey
        "X-Agent-ID" = $CollectorId
        "Content-Type" = "application/json"
    }
    try {
        $resp = Invoke-RestMethod -Uri $SiemIngestUrl -Method Post -Body $jsonPayload -Headers $headers -TimeoutSec 10
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [Heartbeat] Agent pulse sent -> Ingested: $($resp.ingested_count) (Host: $comp, IP: $script:LocalHostIp)" -ForegroundColor DarkCyan
    } catch {
        Write-Warning "Heartbeat warning: $_"
    }
}

# 5. Resolve Channels to Monitor
$channelsToMonitor = @()
if ($Channel -eq "All") {
    $channelsToMonitor = @("Security", "System", "Application")
} else {
    $channelsToMonitor = $Channel.Split(",") | ForEach-Object { $_.Trim() }
}

# 6. Main Execution Loop
if ($Once) {
    $totalIngested = 0
    foreach ($ch in $channelsToMonitor) {
        $totalIngested += Invoke-ChannelPass -Chan $ch
    }
    Write-Host "Single collection completed. Ingested $totalIngested event(s)." -ForegroundColor Cyan
} else {
    Write-Host "Starting continuous real-time collection every $Interval seconds on: $($channelsToMonitor -join ', '). Press Ctrl+C to stop." -ForegroundColor Green
    $idleCycles = 0
    while ($true) {
        $found = 0
        foreach ($ch in $channelsToMonitor) {
            $found += Invoke-ChannelPass -Chan $ch
        }
        if ($found -eq 0) {
            $idleCycles++
            if ($idleCycles -ge 5) { # Send heartbeat every 15s when idle
                $idleCycles = 0
                Invoke-HeartbeatPass
            } else {
                Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Monitoring channels ($($channelsToMonitor -join ', ')). Waiting for new OS events..." -ForegroundColor DarkGray
            }
        } else {
            $idleCycles = 0
        }
        Start-Sleep -Seconds $Interval
    }
}
