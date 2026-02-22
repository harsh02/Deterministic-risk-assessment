#!/usr/bin/env python3
"""Database placeholder generator for development and testing.

Creates minimal empty-structure JSON files for data sources that may not
be available in development environments (CISA KEV, EMB3D, internal
reports).  The risk engine will operate in degraded mode with these
placeholders, relying on keyword extraction and manual overrides.
"""

import json
from pathlib import Path

def create_placeholder_files(data_dir="../data"):
    """Create minimal placeholder JSON files"""
    
    data_path = Path(data_dir)
    
    # Create data directory if it doesn't exist
    data_path.mkdir(parents=True, exist_ok=True)
    
    print("Creating placeholder database files...\n")
    
    # 1. CISA KEV
    kev_file = data_path / "known_exploited_vulnerabilities.json"
    if not kev_file.exists():
        kev_data = {
            "catalogVersion": "2025.10.13",
            "dateReleased": "2025-10-13T00:00:00.000Z",
            "count": 0,
            "vulnerabilities": []
        }
        with open(kev_file, 'w') as f:
            json.dump(kev_data, f, indent=2)
        print(f"✅ Created: {kev_file}")
    else:
        print(f"⏭️  Already exists: {kev_file}")
    
    # 2. EMB3D
    emb3d_file = data_path / "emb3d-stix-2.0.1.json"
    if not emb3d_file.exists():
        emb3d_data = {
            "type": "bundle",
            "id": "bundle--placeholder-emb3d",
            "spec_version": "2.0",
            "objects": []
        }
        with open(emb3d_file, 'w') as f:
            json.dump(emb3d_data, f, indent=2)
        print(f"✅ Created: {emb3d_file}")
    else:
        print(f"⏭️  Already exists: {emb3d_file}")
    
    # 3. Internal Pentest Reports
    reports_file = data_path / "internal_pentest_reports.json"
    if not reports_file.exists():
        reports_data = {
            "version": "1.0",
            "last_updated": "2025-10-13",
            "reports": []
        }
        with open(reports_file, 'w') as f:
            json.dump(reports_data, f, indent=2)
        print(f"✅ Created: {reports_file}")
    else:
        print(f"⏭️  Already exists: {reports_file}")
    
    print("\n" + "="*70)
    print("✅ Placeholder files created successfully!")
    print("="*70)
    print("\n💡 These are empty placeholders. The risk engine will work but:")
    print("   - CVE lookups: Only works if nvdcve-2.0-modified.json exists")
    print("   - KEV checks: Will return 'not exploited' (empty database)")
    print("   - MITRE TTX: Only works if enterprise-attack.json exists")
    print("   - Asset maturity: Will use defaults (empty EMB3D)")
    print("   - Safety detection: Will use keyword matching only")
    print("\n🚀 You can now test with manual overrides:")
    print("   cd src/utils")
    print("   python risk_chat.py")
    print("\n📥 To get real data:")
    print("   - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    print("   - EMB3D: https://github.com/mitre/emb3d")

def check_existing_files(data_dir="../data"):
    """Check which files already exist"""
    
    data_path = Path(data_dir)
    
    print("\n📂 Checking existing database files...\n")
    
    expected_files = {
        "nvdcve-2.0-modified.json": "NVD CVE Database",
        "known_exploited_vulnerabilities.json": "CISA KEV Catalog",
        "enterprise-attack.json": "MITRE ATT&CK",
        "emb3d-stix-2.0.1.json": "EMB3D Threat Model",
        "internal_pentest_reports.json": "Internal Reports"
    }
    
    found = []
    missing = []
    
    for filename, description in expected_files.items():
        filepath = data_path / filename
        if filepath.exists():
            size = filepath.stat().st_size
            size_mb = size / (1024 * 1024)
            print(f"✅ {description:30} ({size_mb:.2f} MB)")
            found.append(filename)
        else:
            print(f"❌ {description:30} (missing)")
            missing.append(filename)
    
    print(f"\n📊 Summary: {len(found)}/{len(expected_files)} files found")
    
    return missing

if __name__ == "__main__":
    print("="*70)
    print(" Database Setup Helper")
    print("="*70)
    
    # Check existing files
    missing = check_existing_files()
    
    if not missing:
        print("\n✅ All database files found! You're ready to go!")
    else:
        print(f"\n⚠️  {len(missing)} file(s) missing")
        response = input("\nCreate placeholder files for missing databases? (y/n): ")
        
        if response.lower() in ['y', 'yes']:
            create_placeholder_files()
        else:
            print("\n💡 Skipped placeholder creation.")
            print("   You can still test with manual overrides:")
            print("   python risk_chat.py")
