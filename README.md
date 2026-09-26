# InvokeHunt

Automated detection testing toolkit — scan, deliver, and validate your binaries against EDR/SIEM engines before they see you first.

Modular pipeline for testing offensive tooling against security products. Each engine gets its own `Invoke-Hunt` script. YARA static analysis and PE metadata checks are shared across all engines.

**Currently supported:**
- Elastic Security (Elastic Defend) — `Invoke-HuntElastic.ps1`

**Planned:**
- Microsoft Defender for Endpoint
- CrowdStrike Falcon

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Python 3.10+ with `yara-python` (`pip install yara-python`)
- Elastic [protections-artifacts](https://github.com/elastic/protections-artifacts) rules cloned locally
- (Optional) Elastic Cloud trial or self-hosted Elastic stack with Elastic Defend

## Quick Start

```powershell
# 1. Clone
git clone https://github.com/RayRRT/InvokeHunt.git
cd InvokeHunt

# 2. Install YARA scanner
pip install yara-python

# 3. Clone Elastic detection rules
git clone --depth 1 https://github.com/elastic/protections-artifacts C:\tools\protections-artifacts

# 4. Copy and edit config
cp config.example.json config.json
# Edit config.json with your Elastic URL and API key

# 5. Run
.\Invoke-HuntElastic.ps1 -Binary .\your_loader.exe
```

## Invoke-HuntElastic

### Usage

```powershell
# Full pipeline (YARA + PE + Delivery + Elastic)
.\Invoke-HuntElastic.ps1 -Binary .\loader.exe

# Quick local test (YARA + PE only, no Elastic)
.\Invoke-HuntElastic.ps1 -Binary .\loader.exe -SkipElastic

# Custom HTTP port and Elastic wait time
.\Invoke-HuntElastic.ps1 -Binary .\loader.exe -Port 9090 -WaitSeconds 60

# Standalone YARA scan (no pipeline)
python yara_scan.py .\loader.exe
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Binary` | Yes | Path to the PE binary (.exe / .dll) to test |
| `-SkipElastic` | No | Skip delivery and Elastic detection phases |
| `-Port` | No | HTTP server port for binary delivery (default: 8080) |
| `-WaitSeconds` | No | Seconds to wait before querying Elastic (default: 30) |
| `-ConfigPath` | No | Path to config file (default: `.\config.json`) |

### Pipeline

```
.\Invoke-HuntElastic.ps1 -Binary .\loader.exe

  [1/5] YARA STATIC ANALYSIS
        Scans against 1000+ Elastic protections-artifacts rules.
        Reports: rule name, severity, matched strings, metadata.
        If detections found: asks to continue or abort.

  [2/5] PE METADATA ANALYSIS
        Checks: entropy, code signing, size, version info.
        Flags: high entropy (packing), unsigned binary, suspicious size.

  [3/5] DELIVERY
        Starts an HTTP server to serve the binary.
        Shows download commands for the target VM.
        Step-by-step: Download confirmed? -> Execute confirmed?
        Options: verify server, re-show commands, custom wait time.

  [4/5] ELASTIC DETECTION CHECK
        Waits for telemetry to reach Elastic.
        Queries via API:
          - Security alerts (YARA, behavioral, memory)
          - Process creation events
          - DLL/library load events
        Reports each alert with rule, severity, and MITRE technique.

  [5/5] VERDICT
        Summary table: PASS / FAIL / SKIP per phase.
        Final verdict: CLEAN, DETECTED, or PARTIAL.
        JSON report saved to results/.
```

### Architecture

```
YOU (dev machine)                          TARGET VM (Elastic Agent)
=================                          ========================

Compile your binary                        Elastic Agent + Elastic
(any language/toolchain)                   Defend in Detect mode
        |
        v
.\Invoke-HuntElastic.ps1 -Binary .\loader.exe
        |
  [1] YARA scan (local)
  [2] PE analysis (local)
  [3] HTTP server ──────────────────> VM downloads binary
  [4] Query Elastic API <──────────── Elastic processes telemetry
  [5] Verdict + JSON report
```

## YARA Scanner (standalone)

`yara_scan.py` can be used independently from the pipeline.

```powershell
# Interactive mode (colored output with detection cards)
python yara_scan.py .\loader.exe

# JSON mode (for automation / scripting)
python yara_scan.py --json .\loader.exe

# Custom rules directory
python yara_scan.py .\loader.exe C:\path\to\yara\rules
```

## Configuration

Copy `config.example.json` to `config.json` and fill in your values:

```json
{
    "yara": {
        "rules_dir": "C:\\tools\\protections-artifacts\\yara\\rules",
        "scanner_script": ".\\yara_scan.py"
    },
    "delivery": {
        "http_port": 8080
    },
    "elastic": {
        "es_url": "https://YOUR-ID.es.cloud.elastic.co:9243",
        "api_key": "YOUR-API-KEY-BASE64",
        "wait_seconds": 30
    },
    "output": {
        "results_dir": ".\\results"
    }
}
```

**Getting an Elastic API key:** Kibana → Stack Management → API Keys → Create API Key.

## Project Structure

```
InvokeHunt/
├── Invoke-HuntElastic.ps1    # Elastic Security pipeline
├── yara_scan.py               # YARA scanner (shared across engines)
├── config.example.json         # Config template
├── config.json                 # Your config (gitignored)
├── results/                    # JSON reports (gitignored)
└── .gitignore
```

## Disclaimer

This tool is intended for authorized security testing, red team engagements, and educational purposes in controlled environments only. The author is not responsible for any misuse.
