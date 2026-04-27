#!/usr/bin/env python3
"""
AbuseIPDB IP Checker - Web GUI (Gradio)
Modern web-based interface accessible via browser
Run with: python abuseipdb_gui_gradio.py
Then open http://localhost:7860 in your browser
"""

import gradio as gr
import requests
import pandas as pd
from datetime import datetime
import re
from typing import List, Dict, Tuple

API_URL = "https://api.abuseipdb.com/api/v2/check"
CRITICAL_THRESHOLD = 90
HIGH_THRESHOLD = 75
MODERATE_THRESHOLD = 25
HIGHLY_REPORTED_THRESHOLD = 50

CRITICAL_INFRASTRUCTURE = {
    'Microsoft': ['Microsoft Corporation', 'Microsoft', 'Azure', 'Office 365'],
    'Google': ['Google LLC', 'Google', 'Google Cloud'],
    'Amazon': ['Amazon.com', 'Amazon', 'AWS'],
    'Cloudflare': ['Cloudflare'],
    'Akamai': ['Akamai'],
}

ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}

def get_abuse_category_names(categories: List[int]) -> str:
    """Convert abuse category IDs to names"""
    if not categories:
        return "None"
    names = [ABUSE_CATEGORIES.get(cat, f"Unknown ({cat})") for cat in categories]
    return ", ".join(names)

def detect_critical_infrastructure(isp: str, domain: str) -> Tuple[bool, str]:
    """Detect if IP belongs to critical infrastructure"""
    for provider, patterns in CRITICAL_INFRASTRUCTURE.items():
        for pattern in patterns:
            if pattern.lower() in isp.lower() or pattern.lower() in domain.lower():
                return True, provider
    return False, "N/A"

def generate_html_report(results: List[Dict], filename: str, microsoft_ips: List, google_ips: List, aws_ips: List):
    """Generate professional HTML report"""
    total = len(results)
    block_now = len([r for r in results if 'BLOCK' in r.get('Action', '') and not r.get('_requires_review')])
    manual_review = len([r for r in results if r.get('_requires_review')])
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AbuseIPDB Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box.red {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .stat-box.yellow {{ background: linear-gradient(135deg, #ffd89b 0%, #f8b500 100%); }}
        .stat-number {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .stat-label {{ font-size: 14px; }}
        .warning-box {{ background: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .critical-box {{ background: #f8d7da; border-left: 5px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #3498db; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: #000; }}
        .badge-safe {{ background: #28a745; color: white; }}
        .timestamp {{ text-align: center; color: #6c757d; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AbuseIPDB Security Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <strong>Total IPs:</strong> {total}</p>
"""
    
    # Critical warnings
    if microsoft_ips or google_ips or aws_ips:
        html += '<div class="critical-box"><h2 style="margin-top:0">⚠️ CRITICAL INFRASTRUCTURE WARNINGS</h2>'
        html += '<p><strong>The following IPs require CLIENT CONFIRMATION before blocking:</strong></p>'
        
        if microsoft_ips:
            html += f'<h3>🔵 Microsoft Infrastructure ({len(microsoft_ips)} IPs)</h3><ul>'
            for ip in microsoft_ips:
                html += f'<li><strong>{ip["IP"]}</strong> - Score: {ip["Score"]} | Reports: {ip["Reports"]}</li>'
            html += '</ul><p><strong>May affect:</strong> Office 365, Azure, Teams, Exchange Online</p>'
        
        html += '</div>'
    
    # Summary stats
    html += f"""
        <h2>📊 Summary Statistics</h2>
        <div class="summary">
            <div class="stat-box">
                <div class="stat-number">{total}</div>
                <div class="stat-label">Total IPs</div>
            </div>
            <div class="stat-box red">
                <div class="stat-number">{block_now}</div>
                <div class="stat-label">Block Recommended</div>
            </div>
            <div class="stat-box yellow">
                <div class="stat-number">{manual_review}</div>
                <div class="stat-label">Manual Review</div>
            </div>
        </div>
        
        <h2>📋 Detailed Results</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Score</th>
                <th>Reports</th>
                <th>Country</th>
                <th>ISP</th>
                <th>Infrastructure</th>
                <th>Recommendation</th>
            </tr>
"""
    
    for r in results:
        if r.get('Score') == 'ERROR':
            continue
        badge_class = 'badge-critical' if '🛑' in r['Recommendation'] else 'badge-warning' if '⚠️' in r['Recommendation'] else 'badge-safe'
        html += f"""
            <tr>
                <td><strong>{r['IP']}</strong></td>
                <td>{r['Score']}</td>
                <td>{r['Reports']}</td>
                <td>{r['Country']}</td>
                <td>{r['ISP'][:40]}...</td>
                <td>{r['Infrastructure']}</td>
                <td><span class="badge {badge_class}">{r['Recommendation']}</span></td>
            </tr>
"""
    
    html += """
        </table>
        <div class="timestamp">
            <p>Report generated by AbuseIPDB Security Analyzer (Python Edition)</p>
            <p>Always verify critical decisions with network administrators</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

def detect_critical_infrastructure(isp: str, domain: str) -> Tuple[bool, str]:
    """Detect if IP belongs to critical infrastructure"""
    for provider, patterns in CRITICAL_INFRASTRUCTURE.items():
        for pattern in patterns:
            if pattern.lower() in isp.lower() or pattern.lower() in domain.lower():
                return True, provider
    return False, "N/A"

def check_ip(ip: str, api_key: str) -> Dict:
    """Check single IP against AbuseIPDB"""
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': ''
    }
    
    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()['data']
        
        # Extract categories
        all_categories = []
        if data.get('reports'):
            for report in data['reports']:
                if report.get('categories'):
                    all_categories.extend(report['categories'])
            all_categories = list(set(all_categories))
        
        categories_text = get_abuse_category_names(all_categories)
        is_highly_reported = data['totalReports'] >= HIGHLY_REPORTED_THRESHOLD
        
        # Detect infrastructure
        isp = data.get('isp', '')
        domain = data.get('domain', '')
        is_critical_infra, provider = detect_critical_infrastructure(isp, domain)
        
        # Blocking recommendation
        score = data['abuseConfidenceScore']
        if data.get('isWhitelisted'):
            recommendation = '✅ NO - WHITELISTED'
            action = 'DO NOT BLOCK'
            requires_review = False
        elif is_critical_infra and score >= MODERATE_THRESHOLD:
            recommendation = '⚠️ MANUAL REVIEW REQUIRED'
            action = 'CONFIRM WITH CLIENT'
            requires_review = True
        elif score >= CRITICAL_THRESHOLD:
            recommendation = '🛑 YES - BLOCK IMMEDIATELY'
            action = 'BLOCK NOW'
            requires_review = False
        elif score >= HIGH_THRESHOLD:
            recommendation = '⛔ YES - BLOCK RECOMMENDED'
            action = 'BLOCK RECOMMENDED'
            requires_review = False
        elif score >= MODERATE_THRESHOLD:
            recommendation = '⚡ REVIEW - INVESTIGATE'
            action = 'INVESTIGATE'
            requires_review = True
        else:
            recommendation = '✅ NO - SAFE TO ALLOW'
            action = 'ALLOW'
            requires_review = False
        
        return {
            'IP': ip,
            'Score': f"{score}%",
            'Reports': data['totalReports'],
            'Highly Reported': '⚠️ YES' if is_highly_reported else 'No',
            'Country': f"{data.get('countryCode', 'N/A')}",
            'ISP': isp or 'Unknown',
            'Infrastructure': f"🏢 {provider}" if is_critical_infra else 'None',
            'Recommendation': recommendation,
            'Action': action,
            'Manual Review': '⚠️ YES' if requires_review else 'No',
            'Abuse Types': categories_text,
            '_score_raw': score,
            '_is_critical_infra': is_critical_infra,
            '_provider': provider,
            '_requires_review': requires_review
        }
    
    except Exception as e:
        return {
            'IP': ip,
            'Score': 'ERROR',
            'Reports': 'ERROR',
            'Highly Reported': 'ERROR',
            'Country': 'ERROR',
            'ISP': str(e),
            'Infrastructure': 'ERROR',
            'Recommendation': f'❌ ERROR: {str(e)}',
            'Action': 'ERROR',
            'Manual Review': 'ERROR',
            'Abuse Types': 'ERROR',
            '_score_raw': 0,
            '_is_critical_infra': False,
            '_provider': None,
            '_requires_review': False
        }

def analyze_ips_batch(api_key: str, ip_list_text: str, file_upload, auto_save_csv: bool, auto_save_html: bool) -> Tuple[pd.DataFrame, str, str, str]:
    """Analyze multiple IPs and return results"""
    if not api_key:
        return pd.DataFrame(), "❌ Error: Please enter your AbuseIPDB API key", "", ""
    
    # Extract IPs from text or file
    ips = []
    if file_upload:
        content = file_upload.decode('utf-8')
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    else:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_list_text)
    
    ips = list(set(ips))  # Remove duplicates
    
    if not ips:
        return pd.DataFrame(), "❌ Error: No valid IP addresses found", "", ""
    
    results = []
    status_messages = []
    
    status_messages.append(f"🔍 Analyzing {len(ips)} IP(s)...\n")
    
    for i, ip in enumerate(ips, 1):
        status_messages.append(f"[{i}/{len(ips)}] Checking {ip}...")
        result = check_ip(ip, api_key)
        results.append(result)
    
    # Create DataFrame for display
    df = pd.DataFrame(results)
    display_columns = ['IP', 'Score', 'Reports', 'Highly Reported', 'Country', 'ISP', 
                      'Infrastructure', 'Recommendation', 'Action', 'Manual Review']
    df_display = df[display_columns]
    
    # Generate summary
    total = len(results)
    block_now = len([r for r in results if 'BLOCK' in r.get('Action', '') and not r.get('_requires_review')])
    manual_review = len([r for r in results if r.get('_requires_review')])
    highly_reported = len([r for r in results if '⚠️ YES' in str(r.get('Highly Reported'))])
    critical_infra = len([r for r in results if r.get('_is_critical_infra')])
    
    microsoft_ips = [r for r in results if r.get('_provider') == 'Microsoft' and r.get('_score_raw', 0) >= MODERATE_THRESHOLD]
    google_ips = [r for r in results if r.get('_provider') == 'Google' and r.get('_score_raw', 0) >= MODERATE_THRESHOLD]
    aws_ips = [r for r in results if r.get('_provider') == 'Amazon' and r.get('_score_raw', 0) >= MODERATE_THRESHOLD]
    
    summary = f"""
## 📊 Analysis Summary

**Total IPs Analyzed:** {total}  
🛑 **Block Immediately:** {block_now}  
⚠️ **Manual Review Required:** {manual_review}  
ℹ️ **Highly Reported:** {highly_reported}  
🏢 **Critical Infrastructure:** {critical_infra}  

---
"""
    
    if microsoft_ips or google_ips or aws_ips:
        summary += "\n## ⚠️⚠️⚠️ CRITICAL INFRASTRUCTURE WARNINGS ⚠️⚠️⚠️\n\n"
        summary += "**The following IPs belong to major cloud providers and require CLIENT CONFIRMATION before blocking:**\n\n"
        
        if microsoft_ips:
            summary += f"### 🔵 MICROSOFT Infrastructure ({len(microsoft_ips)} IP(s))\n\n"
            for ip_data in microsoft_ips:
                summary += f"- **{ip_data['IP']}** - Score: {ip_data['Score']} | Reports: {ip_data['Reports']}\n"
            summary += "\n**⚠️ Blocking may affect:**\n"
            summary += "- Office 365 (Outlook, Teams, OneDrive, SharePoint)\n"
            summary += "- Azure services and cloud infrastructure\n"
            summary += "- Microsoft authentication and SSO\n\n"
        
        if google_ips:
            summary += f"### 🟢 GOOGLE Infrastructure ({len(google_ips)} IP(s))\n\n"
            for ip_data in google_ips:
                summary += f"- **{ip_data['IP']}** - Score: {ip_data['Score']} | Reports: {ip_data['Reports']}\n"
            summary += "\n**⚠️ Blocking may affect:**\n"
            summary += "- Gmail and Google Workspace\n"
            summary += "- Google Cloud Platform services\n\n"
        
        if aws_ips:
            summary += f"### 🟠 AWS Infrastructure ({len(aws_ips)} IP(s))\n\n"
            for ip_data in aws_ips:
                summary += f"- **{ip_data['IP']}** - Score: {ip_data['Score']} | Reports: {ip_data['Reports']}\n"
            summary += "\n**⚠️ Blocking may affect:**\n"
            summary += "- AWS hosted applications and services\n"
            summary += "- S3, EC2, CloudFront resources\n\n"
    
    status_text = "\n".join(status_messages) + "\n\n✅ Analysis complete!"
    
    # Auto-save functionality
    saved_files_info = ""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if auto_save_csv:
        csv_filename = f"abuseipdb_analysis_{timestamp}.csv"
        try:
            # Save full results to CSV
            df_full = pd.DataFrame(results)
            df_full.to_csv(csv_filename, index=False)
            saved_files_info += f"\n✅ **CSV saved:** `{csv_filename}`"
        except Exception as e:
            saved_files_info += f"\n❌ CSV save failed: {str(e)}"
    
    if auto_save_html:
        html_filename = f"abuseipdb_report_{timestamp}.html"
        try:
            generate_html_report(results, html_filename, microsoft_ips, google_ips, aws_ips)
            saved_files_info += f"\n✅ **HTML report saved:** `{html_filename}`"
        except Exception as e:
            saved_files_info += f"\n❌ HTML save failed: {str(e)}"
    
    if saved_files_info:
        summary += f"\n---\n## 💾 Saved Files\n{saved_files_info}\n"
    
    return df_display, summary, status_text, saved_files_info

def create_interface():
    """Create Gradio interface"""
    
    with gr.Blocks(title="AbuseIPDB IP Security Analyzer", theme=gr.themes.Soft()) as app:
        gr.Markdown("""
        # 🛡️ AbuseIPDB IP Security Analyzer
        ### Intelligent Blocking Recommendations with Critical Infrastructure Detection
        
        Analyze IP addresses for abuse reports and get actionable blocking recommendations.  
        Special detection for Microsoft, Google, AWS, and other critical infrastructure.
        """)
        
        with gr.Row():
            with gr.Column():
                api_key = gr.Textbox(
                    label="🔑 AbuseIPDB API Key",
                    placeholder="Enter your API key here...",
                    type="password",
                    info="Get your free API key at abuseipdb.com"
                )
        
        with gr.Row():
            with gr.Column():
                ip_input = gr.Textbox(
                    label="📝 IP Addresses",
                    placeholder="Enter IPs (one per line or comma-separated)\nExample:\n8.8.8.8\n1.1.1.1, 185.220.101.1",
                    lines=8,
                    info="Enter IP addresses to analyze"
                )
                
                file_upload = gr.File(
                    label="📁 Or Upload IP List File",
                    file_types=[".txt"],
                    type="binary"
                )
                
                with gr.Row():
                    auto_save_csv = gr.Checkbox(
                        label="💾 Auto-save CSV",
                        value=True,
                        info="Automatically save results to CSV file"
                    )
                    auto_save_html = gr.Checkbox(
                        label="📊 Auto-save HTML Report",
                        value=True,
                        info="Automatically generate HTML report"
                    )
                
                analyze_btn = gr.Button("🔍 Analyze IPs", variant="primary", size="lg")
        
        with gr.Row():
            with gr.Column():
                summary_output = gr.Markdown(label="Summary")
        
        with gr.Row():
            with gr.Column():
                results_table = gr.Dataframe(
                    label="📊 Analysis Results",
                    interactive=False,
                    wrap=True
                )
        
        with gr.Row():
            with gr.Column():
                status_output = gr.Textbox(
                    label="Status Log",
                    lines=8,
                    interactive=False
                )
        
        with gr.Row():
            with gr.Column():
                saved_files_output = gr.Markdown(
                    label="Saved Files",
                    value="Files will appear here after analysis..."
                )
        
        gr.Markdown("""
        ---
        ### 💡 Tips:
        - **Green recommendations** (✅) = Safe to allow
        - **Red recommendations** (🛑 ⛔) = Block recommended
        - **Yellow warnings** (⚠️) = Requires manual analyst review
        - **Microsoft/Google/AWS IPs** = MUST confirm with client before blocking!
        - **Auto-save enabled by default** - Files saved to current directory
        
        ### 📖 How to Use:
        1. Enter your AbuseIPDB API key (get one free at [abuseipdb.com](https://www.abuseipdb.com))
        2. Enter IP addresses to check (or upload a text file)
        3. Choose auto-save options (CSV and/or HTML)
        4. Click "Analyze IPs"
        5. Files are automatically saved - check the "Saved Files" section below results
        6. For any ⚠️ warnings, confirm with your client before taking action
        """)
        
        # Connect the analyze button
        analyze_btn.click(
            fn=analyze_ips_batch,
            inputs=[api_key, ip_input, file_upload, auto_save_csv, auto_save_html],
            outputs=[results_table, summary_output, status_output, saved_files_output]
        )
        
        # Example inputs
        gr.Examples(
            examples=[
                ["8.8.8.8, 1.1.1.1"],  # Safe IPs
                ["185.220.101.1"],     # Known malicious
            ],
            inputs=[ip_input],
            label="Example IP Lists"
        )
    
    return app

def main():
    """Launch the Gradio app"""
    app = create_interface()
    app.launch(
        server_name="0.0.0.0",  # Allow external connections
        server_port=7860,
        share=False,  # Set to True to create public link
        show_error=True
    )

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║  AbuseIPDB IP Security Analyzer - Web Interface             ║
║  Starting Gradio server...                                   ║
╚══════════════════════════════════════════════════════════════╝

Open your browser and go to: http://localhost:7860

To allow external access, set share=True in the launch() function.
Press Ctrl+C to stop the server.
""")
    main()
