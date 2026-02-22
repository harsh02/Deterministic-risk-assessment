# Industry Configuration Packs

## 📦 Overview

DetRisk provides **industry-specific configuration packs** that tailor risk assessment to different sectors. Each pack uses the common public databases (NVD, KEV, MITRE ATT&CK, EPSS) plus industry-specific data sources and adjusted scoring formulas.

## 🎯 Available Packs

### 1. General IT (Default)
**File:** `general-it.yaml`

**Target:** Enterprise IT, cloud infrastructure, web applications, general software

**Use Cases:**
- Software vulnerabilities (CVE-based)
- Web application security
- Cloud infrastructure threats
- Enterprise network security
- SaaS/API security

**Scoring Priorities:**
- Likelihood: `35% CVSS + 35% KEV + 20% Attack Frequency + 10% EPSS`
- Severity: `70% CVSS Base + 20% Context Criticality + 10% Scope`

**Key Features:**
- Balanced approach across all threat types
- Heavy weight on CVSS and known exploitation
- Suitable for most organizations

---

### 2. ICS/OT/Embedded Systems
**File:** `ics-ot-embedded.yaml`

**Target:** Industrial control systems, SCADA, IoT devices, embedded controllers

**Use Cases:**
- Manufacturing plant SCADA vulnerabilities
- Smart grid and energy infrastructure
- Building automation systems
- IoT device fleet management
- Embedded device firmware security

**Scoring Priorities:**
- **Safety > Availability > Integrity > Confidentiality**
- Likelihood: `25% CVSS + 30% KEV + 15% Freq + 10% EPSS + 10% Device Maturity + 10% Legacy Systems`
- Severity: `40% Safety Impact + 25% Availability + 15% Physical Process + 10% CVSS + 10% Scope`

**Key Features:**
- **Safety impact is paramount** (physical consequences, injuries)
- Availability emphasized over confidentiality
- Legacy system considerations (many ICS devices can't be patched)
- Network segmentation context (air-gapped vs flat network)
- Physical process manipulation detection

**Additional Databases:**
- MITRE ATT&CK for ICS
- EMB3D (embedded device security)
- ICS-CERT advisories
- CWE Hardware weaknesses

**Asset Types:**
- SCADA Server (criticality: 1.0)
- PLC (0.95)
- Safety Instrumented System (1.0)
- HMI (0.9)
- RTU (0.85)

**Example:**
```
Threat: "Modbus TCP unauthenticated access to PLC"
Result:
  Likelihood: 8/10 (Modbus lacks authentication)
  Severity: 10/10 (Safety impact + physical process control)
  Overall: CRITICAL
  Reasoning: Direct PLC control = potential equipment damage or injury
```

---

### 3. Medical Devices / Healthcare
**File:** `medical-devices.yaml`

**Target:** FDA-regulated medical devices, hospital IT, connected medical equipment (IoMT)

**Use Cases:**
- Medical device vulnerabilities
- Hospital network security
- Patient monitoring systems
- Electronic Health Records (EHR)
- Connected medical equipment (IoMT)

**Scoring Priorities:**
- **Patient Safety > PHI Protection > Availability > Integrity**
- Likelihood: `25% CVSS + 30% KEV + 15% Freq + 10% EPSS + 10% Network Connectivity + 10% FDA Recall History`
- Severity: `50% Patient Safety + 20% PHI Exposure + 15% Clinical Workflow + 10% CVSS + 5% Scope`

**Key Features:**
- **Patient safety is highest priority** (life-threatening scenarios)
- HIPAA breach risk assessment (Protected Health Information)
- FDA recall history integration
- Life-sustaining device flagging (2x severity multiplier)
- Clinical workflow impact (ER/ICU vs administrative)
- Regulatory compliance tracking (FDA, HIPAA)

**Additional Databases:**
- FDA MAUDE (adverse event reports)
- FDA Device Recalls
- HHS Breach Portal (HIPAA breaches)
- IoMT Threat Catalog

**Device Classification:**
- Life-sustaining: Ventilator, Pacemaker, Defibrillator (criticality: 1.0)
- Life-supporting: Infusion Pump, Dialysis Machine (0.95)
- Therapeutic: Patient Monitor, Anesthesia Machine (0.8-0.9)
- Diagnostic: MRI, CT Scanner, Laboratory Analyzer (0.6-0.7)

**Regulatory Triggers:**
- Patient Safety Impact ≥ 0.8 → Auto-escalate to Chief Medical Officer
- FDA Class I Recall History → Notify regulatory affairs & legal
- PHI Exposure Risk ≥ 0.6 → HIPAA breach notification required

**Example:**
```
Threat: "Buffer overflow in infusion pump allowing dosage manipulation"
Result:
  Likelihood: 5/10 (Exploitation requires proximity)
  Severity: 10/10 (Life-threatening patient safety impact)
  Overall: CRITICAL
  Regulatory: FDA Class I recall candidate, immediate patient notification
  Reasoning: Unauthorized drug dosage control = patient death risk
```

---

## 📊 Feature Comparison

| Feature | General IT | ICS/OT | Medical Devices |
|---------|-----------|--------|-----------------|
| **Primary Concern** | Data breach | Safety & availability | Patient safety |
| **Confidentiality** | High priority | Low priority | High (PHI) |
| **Availability** | Medium priority | Highest priority | High priority |
| **Integrity** | Medium priority | High priority | High priority |
| **Physical Safety** | N/A | Paramount | Paramount |
| **Regulatory Context** | Minimal | NERC, NIST | FDA, HIPAA |
| **Patching Difficulty** | Easy | Hard (legacy) | Very hard (validation) |
| **Network Exposure** | Internet-facing | Often air-gapped | Hospital network |
| **Response Time** | Days | Hours | Immediate |

---

## 🗂️ Database Requirements

### Common Databases (All Packs)
These are shared across all industry packs:

- ✅ **NVD CVE Database** - CVE vulnerability data
- ✅ **CISA KEV** - Known exploited vulnerabilities
- ✅ **MITRE ATT&CK** - Attack patterns and techniques
- ✅ **EPSS** - Exploit prediction scores

### Industry-Specific Databases

**ICS/OT Pack:**
- 🔧 **MITRE ATT&CK for ICS** - Industrial control system tactics
- 🔧 **ICS-CERT Advisories** - CISA ICS vulnerability advisories
- 🔧 **EMB3D** - Embedded device security database
- 🔧 **CWE Hardware** - Hardware-specific weaknesses

**Medical Devices Pack:**
- 🏥 **FDA MAUDE** - Medical device adverse event reports
- 🏥 **FDA Recalls** - Medical device recall database
- 🏥 **HHS Breach Portal** - Healthcare data breach notifications
- 🏥 **IoMT Threats** - Internet of Medical Things threat catalog

---

## 🚀 Quick Start

### 1. Choose Your Industry Pack

```bash
# General IT (default)
python src/utils/run_risk.py --config policy/industry-packs/general-it.yaml

# ICS/OT/Embedded
python src/utils/run_risk.py --config policy/industry-packs/ics-ot-embedded.yaml

# Medical Devices
python src/utils/run_risk.py --config policy/industry-packs/medical-devices.yaml
```

### 2. Test with Example Threats

**General IT Example:**
```bash
echo '{
  "cve": "CVE-2024-21413",
  "title": "Microsoft Outlook RCE",
  "description": "Remote code execution vulnerability"
}' | python src/utils/risk_chat.py --config policy/industry-packs/general-it.yaml
```

**ICS Example:**
```bash
echo '{
  "title": "Modbus TCP Vulnerability in SCADA",
  "description": "Unauthenticated access to PLC registers",
  "asset": "PLC",
  "protocol": "Modbus"
}' | python src/utils/risk_chat.py --config policy/industry-packs/ics-ot-embedded.yaml
```

**Medical Device Example:**
```bash
echo '{
  "title": "Buffer Overflow in Infusion Pump",
  "description": "Remote code execution allowing dosage changes",
  "device_type": "Infusion_Pump"
}' | python src/utils/risk_chat.py --config policy/industry-packs/medical-devices.yaml
```

---

## ⚙️ Customization

### Adjust Weights

Edit the formula in your chosen pack:

```yaml
# policy/industry-packs/your-pack.yaml
scoring:
  likelihood:
    formula: |
      0.35*CVSS_Exploitability +
      0.35*KnownExploited +
      0.20*Attack_Frequency +
      0.10*EPSS_Score
```

### Add Custom Features

```yaml
features:
  - name: Custom_Context_Score
    from: ["internal_db"]
    description: "Your organization-specific risk factor"
    default: 0.5
    enabled: false
```

### Enable Industry-Specific Features

Many features are disabled by default (require internal data):

```yaml
features:
  - name: Network_Segmentation
    from: ["internal_reports"]
    enabled: true  # Enable when you have data
    default: 0.5
```

---

## 📥 Download Industry Databases

### ICS/OT Databases

```bash
# MITRE ATT&CK for ICS
wget https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json \
  -O data/ics-attack.json

# ICS-CERT Advisories (requires API key or scraping)
# Visit: https://www.cisa.gov/ics-cert-advisories

# EMB3D
git clone https://github.com/mitre/emb3d.git
cp emb3d/data/emb3d-stix-2.0.1.json data/
```

### Medical Device Databases

```bash
# FDA MAUDE (requires FDA API or manual download)
# Visit: https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfmaude/search.cfm

# FDA Device Recalls
# Visit: https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfres/res.cfm

# HHS Breach Portal
wget https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf \
  -O data/hhs-breach-portal.csv
```

---

## 🎯 Use Case Examples

### Use Case 1: Manufacturing Plant

**Scenario:** Vulnerability in factory floor SCADA system

**Pack:** ICS/OT/Embedded

**Input:**
```
Title: "CVE-2024-XXXXX SQL Injection in HMI Software"
Asset: HMI
Safety Impact: Moderate (equipment damage possible)
```

**Output:**
```
Likelihood: 6/10
Severity: 8/10 (Safety multiplier applied)
Risk: HIGH
Recommendation: Immediate patching with production downtime window
```

---

### Use Case 2: Hospital Network

**Scenario:** Vulnerability in patient monitoring system

**Pack:** Medical Devices

**Input:**
```
Title: "Unencrypted network traffic in patient monitor"
Device: Patient_Monitor
Network: Hospital_Network
PHI Exposure: Individual_PHI
```

**Output:**
```
Likelihood: 5/10
Severity: 6/10 (PHI + workflow impact)
Risk: MEDIUM
Regulatory: HIPAA security rule violation, corrective action required
Recommendation: Implement network encryption, segment medical VLAN
```

---

### Use Case 3: SaaS Application

**Scenario:** CVE in web framework

**Pack:** General IT

**Input:**
```
CVE: CVE-2024-21413
Title: "Remote code execution in authentication module"
Asset: Backend_API
```

**Output:**
```
Likelihood: 8/10 (Known exploited + high EPSS)
Severity: 9/10 (CVSS 9.8, customer data at risk)
Risk: CRITICAL
Recommendation: Emergency patch deployment, investigate for exploitation
```

---

## 🔄 Migration Guide

### From General IT → ICS/OT

1. Download ICS-specific databases (ATT&CK for ICS, ICS-CERT)
2. Map your assets to ICS types (PLC, HMI, SCADA, RTU)
3. Document safety impact assessments
4. Enable `Safety_Impact` and `Physical_Process_Impact` features
5. Test with sample ICS threats

### From General IT → Medical Devices

1. Download medical databases (FDA MAUDE, recalls)
2. Classify devices by FDA class (I, II, III)
3. Flag life-sustaining devices
4. Enable `Patient_Safety_Impact` and `PHI_Exposure_Risk` features
5. Set up regulatory notification workflows
6. Test with sample medical device threats

---

## 📚 Additional Resources

### Standards & Frameworks

**ICS/OT:**
- NIST SP 800-82: Guide to ICS Security
- IEC 62443: Industrial Automation Security
- NERC CIP: Critical Infrastructure Protection

**Medical Devices:**
- FDA Premarket Cybersecurity Guidance
- FDA Postmarket Cybersecurity Guidance
- AAMI TIR57: Medical Device Security Risk Management
- IEC 80001: Network Security for Medical Devices

**General:**
- NIST Cybersecurity Framework
- MITRE ATT&CK
- CWE Top 25

---

## 🤝 Contributing

Want to add a new industry pack?

1. Copy an existing pack as a template
2. Identify industry-specific databases
3. Define custom features and weights
4. Test with real-world scenarios
5. Submit a pull request with examples

**Potential future packs:**
- Financial Services (PCI-DSS, SOX)
- Automotive (UNECE WP.29, ISO 21434)
- Aerospace/Defense (NIST 800-171)
- Smart Cities (IoT at scale)
- Energy/Utilities (NERC CIP)

---

## 📄 License

MIT License - Same as main project

---

**Questions?** Open an issue or check the main [README](../../README.md)
