# Database Setup Issues & Solutions

## Current Status

### ✅ Files Found
- `enterprise-attack.json` - MITRE ATT&CK data
- `nvdcve-2.0-modified.json` - NVD CVE data

### ⚠️ Missing/Format Issues

1. **CISA KEV Database**
   - Expected: `known_exploited_vulnerabilities.json`
   - Found: `cisa_known_exploited_v...ilities.pdf` (PDF format)
   - **Action Needed**: Download JSON version from CISA

2. **EMB3D Threat Model**
   - Expected: `emb3d-stix-2.0.1.json`
   - Not visible in screenshot
   - **Action Needed**: Download or create placeholder

3. **Internal Pentest Reports**
   - Expected: `internal_pentest_reports.json`
   - Not visible in screenshot
   - **Action Needed**: Create placeholder or use actual data

4. **EPSS Scores**
   - Found: `epss_scores-2025-10-02.csv.gz`
   - Not configured in risk engine
   - **Optional**: Can be added later
   - **Note**: Public endpoint may return HTTP 403. When that happens run the sync script in manual mode (see below) or download the CSV/GZ manually from FIRST.

## Quick Fixes

### Option 1: Test with Manual Overrides Only (No DB needed)

You can test the Chat CLI immediately using manual overrides:

```bash
cd <project-root>/src/utils
python risk_chat.py
```

Then input:
```
Buffer overflow in medical device cvss=8.5 exp=3.9 kev=1 af=0.6 sm=0.3 safety=1 asset=SafetyCriticalDevice
```

This will work without any database files!

### Option 2: Use the sync script (preferred)

```bash
cd <project-root>
python scripts/sync_intel_feeds.py --only kev
```

If NVD or EPSS downloads are blocked with HTTP 403 responses the script prints the manual download URLs. Place the retrieved files under `data/` as documented below.

### Option 3: Download Missing JSON Files Manually

#### 1. CISA KEV (JSON format)
```bash
cd <project-root>/data
curl -O https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

#### 2. EMB3D (STIX format)
```bash
cd <project-root>/data
curl -L -O https://github.com/mitre/emb3d/releases/download/v1.0.0/emb3d-stix-2.0.1.json
```

### Option 4: Create Placeholder Files

Create minimal JSON files for testing:

#### Create `known_exploited_vulnerabilities.json`:
```json
{
  "catalogVersion": "2025.10.13",
  "dateReleased": "2025-10-13T00:00:00.000Z",
  "count": 0,
  "vulnerabilities": []
}
```

#### Create `internal_pentest_reports.json`:
```json
{
  "reports": []
}
```

#### Create `emb3d-stix-2.0.1.json`:
```json
{
  "type": "bundle",
  "id": "bundle--placeholder",
  "objects": []
}
```

## Testing Strategy

### Phase 1: Manual Overrides (Works Now!)
Test the risk scoring without databases:
```bash
python risk_chat.py
# Then type: cvss=7.5 exp=3.8 kev=1 af=0.5 sm=0.3 safety=1
```

### Phase 2: With CVE Data (Partial DB)
Test with the files you already have:
- ✅ `nvdcve-2.0-modified.json` - CVE lookups will work
- ✅ `enterprise-attack.json` - MITRE technique lookups will work

Input example:
```
CVE-2024-12345 with T1190 attack pattern
```

### Phase 3: Full Database Integration
After downloading/creating all files, test complete auto-resolution:
```
CVE-2024-12345 in Selenia Dimensions with patient safety risk
```

## Recommended Next Steps

1. **Test Now** - Run with manual overrides (no setup needed)
   ```bash
   cd <project-root>/src/utils
   python preflight_check.py  # Check what works
   python risk_chat.py         # Start testing
   ```

2. **Download CISA KEV JSON** - Most important missing file

3. **Create placeholder files** - For EMB3D and internal reports

4. **Test incrementally** - Verify each database integration works

## File Locations Expected

Your config expects files here:
```
<project-root>/
├── data/
│   ├── nvdcve-2.0-modified.json              ✅ (you have this)
│   ├── known_exploited_vulnerabilities.json  ❌ (need JSON, not PDF)
│   ├── enterprise-attack.json                ✅ (you have this)
│   ├── emb3d-stix-2.0.1.json                ❌ (missing)
│   └── internal_pentest_reports.json        ❌ (missing)
```

## Quick Commands to Create Placeholders

```bash
# Navigate to data directory
cd <project-root>/data

# Create KEV placeholder
echo '{"catalogVersion":"2025.10.13","vulnerabilities":[]}' > known_exploited_vulnerabilities.json

# Create EMB3D placeholder  
echo '{"type":"bundle","objects":[]}' > emb3d-stix-2.0.1.json

# Create internal reports placeholder
echo '{"reports":[]}' > internal_pentest_reports.json
```

After running these commands, the Chat CLI will work with full auto-detection!

## Verification

After setup, run:
```bash
cd <project-root>/src/utils
python preflight_check.py
```

This will show you which files are found and which are missing.
