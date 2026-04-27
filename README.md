# 🛡️ AbuseIPDB Security Analyzer

> **Intelligent IP Threat Analysis with Critical Infrastructure Protection**

A powerful Python-based security tool for analyzing IP addresses against the AbuseIPDB database with intelligent blocking recommendations and special detection for Microsoft, Google, AWS, and other critical infrastructure.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

---

## 📋 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [GUI Options](#-gui-options)
- [Advanced Features](#-advanced-features)
- [Best Practices](#-best-practices)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Author](#-author)

---

## ✨ Features

### 🎯 Core Capabilities

- **Comprehensive IP Analysis** - 18+ data points per IP including score, reports, location, ISP, and more
- **Intelligent Blocking Recommendations** - Automated security decisions based on threat level
- **Highly Reported Detection** - Automatic flagging of IPs with 50+ abuse reports
- **Multi-format Export** - CSV, JSON, and professional HTML reports
- **Batch Processing** - Analyze multiple IPs from text input or file upload
- **Real-time Analysis** - Live threat assessment with progress tracking

### 🏢 Critical Infrastructure Protection

**⚠️ SPECIAL FEATURE: Microsoft/Google/AWS Detection**

Automatically detects and warns when highly-reported IPs belong to:
- 🔵 **Microsoft** (Office 365, Azure, Teams, Exchange)
- 🟢 **Google** (Gmail, Workspace, GCP)
- 🟠 **Amazon AWS** (EC2, S3, CloudFront)
- **Cloudflare, Akamai, Oracle Cloud, and more**

**Why This Matters:**
Blocking these IPs could disrupt critical business services. The tool requires **manual analyst confirmation** before recommending blocks on infrastructure IPs, preventing accidental service disruption.

### 📊 Risk Assessment Levels

| Score | Classification | Recommendation | Action |
|-------|---------------|----------------|--------|
| 90-100% | 🚨 **CRITICAL** | Block Immediately | Auto-block safe |
| 75-89% | ⛔ **HIGH** | Block Recommended | Review & block |
| 50-74% | ⚠️ **ELEVATED** | Investigate Further | Manual review |
| 25-49% | ⚡ **MODERATE** | Monitor Closely | Investigate |
| 10-24% | ℹ️ **LOW** | Minimal Threat | Allow |
| 0-9% | ✅ **MINIMAL** | Safe to Allow | Whitelist |

### 💾 Auto-Save Functionality

- **Automatic CSV Export** - All results saved to timestamped CSV files
- **Professional HTML Reports** - Beautiful, shareable reports with visual warnings
- **Timestamp-Based Naming** - Never overwrite previous analyses
- **Configurable Options** - Enable/disable auto-save per analysis

### 🎨 Dual GUI Options

1. **Web Interface (Gradio)** ⭐ *Recommended*
   - Modern web-based UI
   - Mobile-friendly responsive design
   - Share via URL with team
   - No installation needed for users
   - Interactive data tables

2. **Desktop Application (tkinter)**
   - Native desktop experience
   - Offline operation
   - Fast and lightweight
   - Cross-platform compatibility

---

## 📸 Screenshots

### Web Interface (Gradio)

```
╔══════════════════════════════════════════════════════════╗
║       🛡️ AbuseIPDB IP Security Analyzer                  ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  🔑 API Key: [**********************]                    ║
║                                                          ║
║  📝 IP Addresses:                                        ║
║  ┌────────────────────────────────────────────────────┐  ║
║  │ 185.220.101.1                                      │  ║
║  │ 40.97.156.58                                       │  ║
║  └────────────────────────────────────────────────────┘  ║
║                                                          ║
║  [✓] 💾 Auto-save CSV    [✓] 📊 Auto-save HTML         ║
║                                                          ║
║              [🔍 Analyze IPs]                            ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  📊 Analysis Summary                                     ║
║  ─────────────────────────────────────────────────────   ║
║  Total IPs: 2                                           ║
║  🛑 Block Immediately: 1                                ║
║  ⚠️ Manual Review Required: 1                           ║
║                                                          ║
║  ⚠️⚠️⚠️ MICROSOFT INFRASTRUCTURE WARNING ⚠️⚠️⚠️         ║
║  • 40.97.156.58 - Score 82% | Reports: 127             ║
║    May affect: Office 365, Azure, Teams                ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package installer)
- **AbuseIPDB API Key** (free at [abuseipdb.com](https://www.abuseipdb.com/register))

### Step 1: Clone the Repository

```bash
git clone https://github.com/ali5aled/abuseipdb-security-analyzer.git
cd abuseipdb-security-analyzer
```

### Step 2: Install Required Packages

#### Option A: Using pip directly

```bash
pip install requests gradio pandas
```

#### Option B: Using requirements.txt

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
requests>=2.31.0
gradio>=4.16.0
pandas>=2.1.0
```

#### Option C: Using Virtual Environment (Recommended)

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Kali Linux (Special Instructions):**
```bash
# If you get "externally-managed-environment" error:
python3 -m venv venv
source venv/bin/activate
pip install requests gradio pandas

# Or use --break-system-packages:
pip3 install --break-system-packages requests gradio pandas
```

### Step 3: Configure API Key

Open the script you want to use and add your API key:

```python
# In abuseipdb_gui_gradio.py or abuseipdb_gui_tkinter.py
API_KEY = "your_actual_api_key_here"
```

Or enter it in the GUI when prompted.

### Package Requirements

| Package | Purpose | Minimum Version |
|---------|---------|-----------------|
| `requests` | API communication | 2.31.0 |
| `gradio` | Web interface | 4.16.0 |
| `pandas` | Data handling | 2.1.0 |

---

## ⚡ Quick Start

### Using Web Interface (Gradio) - Recommended

```bash
# 1. Navigate to project directory
cd abuseipdb-security-analyzer

# 2. Activate virtual environment (if using one)
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# 3. Run the web interface
python abuseipdb_gui_gradio.py

# 4. Open your browser to: http://localhost:7860
```

### Using Desktop Application (tkinter)

```bash
python abuseipdb_gui_tkinter.py
```

### Using Command-Line Interface

```bash
python abuseipdb_checker.py
```

---

## 📖 Usage Guide

### Basic Workflow

1. **Enter API Key**
   - Get free key at [abuseipdb.com/register](https://www.abuseipdb.com/register)
   - Free tier: 1,000 checks/day

2. **Input IP Addresses**
   - **Manual:** Type or paste IPs (comma-separated or one per line)
   - **File Upload:** Upload .txt file with IPs

3. **Configure Auto-Save** (Optional)
   - ✅ Auto-save CSV - For data analysis
   - ✅ Auto-save HTML Report - For presentations

4. **Analyze**
   - Click "Analyze IPs" button
   - Wait for results (progress shown)

5. **Review Results**
   - Check blocking recommendations
   - ⚠️ **IMPORTANT:** Verify any Microsoft/Google/AWS warnings

6. **Take Action**
   - **🛑 Block Immediately** - Safe to block
   - **⚠️ Manual Review** - Confirm with client first
   - **✅ Safe to Allow** - No action needed

---

## 🎨 GUI Options

### 🌐 Option 1: Web Interface (Gradio) ⭐ Recommended

**Best For:**
- Team environments
- Remote access
- Mobile devices
- Non-technical users
- Sharing via URL

**Starting:**
```bash
python abuseipdb_gui_gradio.py
```
**Access:** http://localhost:7860

**Team Deployment:**
```bash
# Run on server - team accesses via URL
python abuseipdb_gui_gradio.py
# Access at: http://server-ip:7860
```

---

### 🖥️ Option 2: Desktop Application (tkinter)

**Best For:**
- Offline analysis
- Personal use
- Fast performance
- Traditional desktop feel

**Starting:**
```bash
python abuseipdb_gui_tkinter.py
```

---

## 🔥 Advanced Features

### Batch Processing from File

Create a text file with IPs:
```bash
# ips_to_check.txt
8.8.8.8
1.1.1.1
185.220.101.1
```

Upload in GUI or reference in code.

### Automated Daily Checks

```bash
#!/bin/bash
# daily_ip_check.sh

# Extract IPs from logs
grep "BLOCK" /var/log/firewall.log | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' > today_blocks.txt

# Analyze
cd ~/abuseipdb-security-analyzer
source venv/bin/activate
python abuseipdb_checker.py < today_blocks.txt
```

### Integration with SIEM

Export results to feed into your SIEM:
```bash
# Analyze and export to JSON
python abuseipdb_checker.py --export-json

# Import to SIEM
./import_to_siem.sh abuseipdb_results.json
```

---

## 💡 Best Practices

### For Security Analysts

1. ✅ **Always verify Microsoft/Google/AWS IPs with client**
2. ✅ Review recent abuse reports and categories
3. ✅ Document all blocking decisions
4. ✅ Keep HTML reports for audit trail
5. ✅ Re-check previously blocked IPs periodically

### For SOC Teams

1. ✅ Deploy web interface on team server
2. ✅ Standardize blocking thresholds
3. ✅ Create escalation procedures for infrastructure IPs
4. ✅ Train team on the tool (takes ~2 minutes)
5. ✅ Integrate with existing workflows

### Critical Infrastructure Rules

**NEVER auto-block if:**
- IP belongs to Microsoft/Google/AWS/Cloudflare
- Score is high BUT infrastructure is critical
- Client hasn't confirmed

**ALWAYS confirm with client when:**
- Microsoft IP is flagged (may affect Office 365, Teams, Azure)
- Google IP is flagged (may affect Gmail, Workspace)
- AWS IP is flagged (may affect cloud applications)

---

## 🔧 Troubleshooting

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| `pip: command not found` | Use `python -m pip install ...` |
| `externally-managed-environment` (Linux) | Use virtual environment or `--break-system-packages` flag |
| Port 7860 already in use | Edit script and change port: `server_port=7861` |
| SSL Certificate Error | Run `pip install --upgrade certifi` |
| Permission Denied | Use `pip install --user ...` |

### Getting Help

1. Check [GitHub Issues](https://github.com/ali5aled/abuseipdb-security-analyzer/issues)
2. Review this README
3. Check [AbuseIPDB API Documentation](https://docs.abuseipdb.com)

---

## 📊 Data Fields Collected

The tool collects **18+ data points** per IP:

- IP Address, Abuse Score, Total Reports
- Highly Reported Flag (50+ reports)
- Country, ISP, Domain, Hostnames
- Usage Type (ISP/Data Center/Business)
- Whitelist Status, Tor Detection
- Last Reported Date
- Abuse Categories (Port Scan, Brute-Force, etc.)
- Infrastructure Provider (Microsoft/Google/AWS)
- Blocking Recommendation
- Manual Review Required Flag

---

## 🤝 Contributing

Contributions welcome! Feel free to submit pull requests.

### How to Contribute

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 🎯 Roadmap

- [ ] Additional cloud provider detection
- [ ] Historical trend analysis
- [ ] Docker container
- [ ] API endpoint for automation
- [ ] Webhook notifications
- [ ] Multi-language support

---

## ⭐ Show Your Support

If this tool helped you:
- ⭐ Star this repository
- 🐛 Report bugs
- 💡 Suggest features
- 🔀 Contribute code
- 📢 Share with colleagues

---

## 👤 Author

**Ali Khaled**

- GitHub: [@ali5aled](https://github.com/ali5aled)
- Role: Security Analyst & Tool Developer

*Created with ❤️ for the security community*

---

## 🙏 Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com) for the excellent API
- [Gradio](https://gradio.app) for the web interface framework
- The open-source security community

---

## ⚠️ Disclaimer

This tool is for security analysis purposes. Always:
- Verify results before blocking
- Confirm with stakeholders before blocking critical infrastructure
- Follow your organization's security policies
- Use responsibly and ethically

**The author is not responsible for service disruptions or damages caused by misuse.**

---

<div align="center">

**Made with 🛡️ for Security Professionals**

[⬆ Back to Top](#️-abuseipdb-security-analyzer)

</div>
