#!/usr/bin/env python3
"""
AbuseIPDB IP Checker - Desktop GUI (tkinter)
Simple cross-platform desktop interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import requests
from datetime import datetime
from pathlib import Path
import csv
import json
import re

# Import core functions from main script
# (In production, these would be in a separate module)

API_URL = "https://api.abuseipdb.com/api/v2/check"
CRITICAL_THRESHOLD = 90
HIGH_THRESHOLD = 75
MODERATE_THRESHOLD = 25
HIGHLY_REPORTED_THRESHOLD = 50

CRITICAL_INFRASTRUCTURE = {
    'Microsoft': ['Microsoft Corporation', 'Microsoft', 'Azure', 'Office 365'],
    'Google': ['Google LLC', 'Google', 'Google Cloud'],
    'Amazon': ['Amazon.com', 'Amazon', 'AWS'],
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

class AbuseIPDBApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AbuseIPDB IP Security Analyzer")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        self.results = []
        self.api_key = tk.StringVar()
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', pady=15)
        title_frame.pack(fill='x')
        
        title_label = tk.Label(title_frame, text="🛡️ AbuseIPDB IP Security Analyzer", 
                              font=('Arial', 18, 'bold'), bg='#2c3e50', fg='white')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Intelligent Blocking Recommendations with Critical Infrastructure Detection", 
                                 font=('Arial', 10), bg='#2c3e50', fg='#ecf0f1')
        subtitle_label.pack()
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # API Key Section
        api_frame = tk.LabelFrame(main_frame, text="API Configuration", font=('Arial', 10, 'bold'), 
                                 bg='#f0f0f0', padx=10, pady=10)
        api_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(api_frame, text="AbuseIPDB API Key:", bg='#f0f0f0').grid(row=0, column=0, sticky='w')
        api_entry = tk.Entry(api_frame, textvariable=self.api_key, width=50, show='*')
        api_entry.grid(row=0, column=1, padx=5, sticky='ew')
        
        tk.Button(api_frame, text="Show/Hide", command=lambda: api_entry.config(show='' if api_entry.cget('show') == '*' else '*'),
                 bg='#95a5a6', fg='white').grid(row=0, column=2, padx=5)
        
        api_frame.columnconfigure(1, weight=1)
        
        # IP Input Section
        input_frame = tk.LabelFrame(main_frame, text="IP Addresses to Check", font=('Arial', 10, 'bold'), 
                                   bg='#f0f0f0', padx=10, pady=10)
        input_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        tk.Label(input_frame, text="Enter IPs (one per line or comma-separated):", bg='#f0f0f0').pack(anchor='w')
        
        self.ip_input = scrolledtext.ScrolledText(input_frame, height=8, width=80, font=('Consolas', 10))
        self.ip_input.pack(fill='both', expand=True, pady=5)
        
        # Buttons frame
        button_frame = tk.Frame(input_frame, bg='#f0f0f0')
        button_frame.pack(fill='x', pady=5)
        
        tk.Button(button_frame, text="📁 Load from File", command=self.load_from_file,
                 bg='#3498db', fg='white', font=('Arial', 10), padx=10).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="🔍 Analyze IPs", command=self.analyze_ips,
                 bg='#27ae60', fg='white', font=('Arial', 10, 'bold'), padx=20).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="🗑️ Clear", command=self.clear_all,
                 bg='#e74c3c', fg='white', font=('Arial', 10), padx=10).pack(side='left', padx=5)
        
        # Auto-save options
        autosave_frame = tk.Frame(input_frame, bg='#f0f0f0')
        autosave_frame.pack(fill='x', pady=5)
        
        self.auto_save_csv = tk.BooleanVar(value=True)
        self.auto_save_html = tk.BooleanVar(value=True)
        
        tk.Checkbutton(autosave_frame, text="💾 Auto-save CSV", variable=self.auto_save_csv,
                      bg='#f0f0f0', font=('Arial', 9)).pack(side='left', padx=10)
        tk.Checkbutton(autosave_frame, text="📊 Auto-save HTML Report", variable=self.auto_save_html,
                      bg='#f0f0f0', font=('Arial', 9)).pack(side='left', padx=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill='x', pady=(0, 10))
        
        # Results Section
        results_frame = tk.LabelFrame(main_frame, text="Analysis Results", font=('Arial', 10, 'bold'), 
                                     bg='#f0f0f0', padx=10, pady=10)
        results_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80, 
                                                     font=('Consolas', 9), bg='#2c3e50', fg='#ecf0f1',
                                                     insertbackground='white')
        self.results_text.pack(fill='both', expand=True)
        
        # Configure text tags for colors
        self.results_text.tag_config('critical', foreground='#e74c3c', font=('Consolas', 9, 'bold'))
        self.results_text.tag_config('warning', foreground='#f39c12', font=('Consolas', 9, 'bold'))
        self.results_text.tag_config('success', foreground='#27ae60', font=('Consolas', 9, 'bold'))
        self.results_text.tag_config('info', foreground='#3498db')
        self.results_text.tag_config('header', foreground='#ecf0f1', font=('Consolas', 9, 'bold'))
        
        # Export buttons
        export_frame = tk.Frame(main_frame, bg='#f0f0f0')
        export_frame.pack(fill='x')
        
        tk.Button(export_frame, text="💾 Export CSV", command=lambda: self.export_results('csv'),
                 bg='#16a085', fg='white', font=('Arial', 10), padx=10).pack(side='left', padx=5)
        
        tk.Button(export_frame, text="📄 Export JSON", command=lambda: self.export_results('json'),
                 bg='#8e44ad', fg='white', font=('Arial', 10), padx=10).pack(side='left', padx=5)
        
        tk.Button(export_frame, text="📊 Export HTML Report", command=lambda: self.export_results('html'),
                 bg='#d35400', fg='white', font=('Arial', 10), padx=10).pack(side='left', padx=5)
    
    def load_from_file(self):
        """Load IPs from text file"""
        filename = filedialog.askopenfilename(
            title="Select IP list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, 'r') as f:
                content = f.read()
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                self.ip_input.delete('1.0', tk.END)
                self.ip_input.insert('1.0', '\n'.join(set(ips)))
            
            messagebox.showinfo("Success", f"Loaded {len(set(ips))} unique IPs")
    
    def clear_all(self):
        """Clear inputs and results"""
        self.ip_input.delete('1.0', tk.END)
        self.results_text.delete('1.0', tk.END)
        self.results = []
    
    def analyze_ips(self):
        """Start IP analysis in background thread"""
        if not self.api_key.get():
            messagebox.showerror("Error", "Please enter your AbuseIPDB API key")
            return
        
        ip_text = self.ip_input.get('1.0', tk.END).strip()
        if not ip_text:
            messagebox.showerror("Error", "Please enter at least one IP address")
            return
        
        # Parse IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_text)
        ips = list(set(ips))  # Remove duplicates
        
        if not ips:
            messagebox.showerror("Error", "No valid IP addresses found")
            return
        
        # Clear previous results
        self.results_text.delete('1.0', tk.END)
        self.results = []
        
        # Start analysis in background thread
        self.progress.start()
        thread = threading.Thread(target=self.run_analysis, args=(ips,))
        thread.daemon = True
        thread.start()
    
    def run_analysis(self, ips):
        """Run analysis in background thread"""
        self.append_result("═" * 80 + "\n", 'header')
        self.append_result(f"🔍 Analyzing {len(ips)} IP address(es)...\n", 'header')
        self.append_result("═" * 80 + "\n\n", 'header')
        
        for i, ip in enumerate(ips, 1):
            self.append_result(f"[{i}/{len(ips)}] Checking: {ip}\n", 'info')
            
            result = self.check_ip(ip)
            if result:
                self.results.append(result)
                self.display_result(result)
        
        # Summary
        self.append_result("\n" + "═" * 80 + "\n", 'header')
        self.append_result("📊 ANALYSIS SUMMARY\n", 'header')
        self.append_result("═" * 80 + "\n\n", 'header')
        
        block_now = len([r for r in self.results if 'BLOCK' in r.get('recommended_action', '') and not r.get('requires_manual_review')])
        manual_review = len([r for r in self.results if r.get('requires_manual_review')])
        highly_reported = len([r for r in self.results if r.get('is_highly_reported')])
        critical_infra = len([r for r in self.results if r.get('is_critical_infrastructure')])
        
        self.append_result(f"Total IPs: {len(ips)}\n", 'info')
        self.append_result(f"🛑 Block Immediately: {block_now}\n", 'critical')
        self.append_result(f"⚠️ Manual Review Required: {manual_review}\n", 'warning')
        self.append_result(f"ℹ️ Highly Reported: {highly_reported}\n", 'warning')
        self.append_result(f"🏢 Critical Infrastructure: {critical_infra}\n", 'info')
        
        # Critical warnings
        microsoft_ips = [r for r in self.results if r.get('infrastructure_provider') == 'Microsoft' 
                        and r.get('abuse_confidence_score', 0) >= MODERATE_THRESHOLD]
        
        if microsoft_ips:
            self.append_result("\n" + "╔" + "═" * 78 + "╗\n", 'critical')
            self.append_result("║  ⚠️ MICROSOFT INFRASTRUCTURE WARNINGS - CONFIRM WITH CLIENT  ⚠️     ║\n", 'critical')
            self.append_result("╚" + "═" * 78 + "╝\n", 'critical')
            for ip_data in microsoft_ips:
                self.append_result(f"\n  IP: {ip_data['ip']}\n", 'warning')
                self.append_result(f"  Score: {ip_data['abuse_confidence_score']}% | Reports: {ip_data['total_reports']}\n", 'warning')
        
        self.progress.stop()
        
        # Auto-save functionality
        saved_files = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.auto_save_csv.get() and self.results:
            csv_filename = f"abuseipdb_analysis_{timestamp}.csv"
            try:
                with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = list(self.results[0].keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.results)
                saved_files.append(f"CSV: {csv_filename}")
            except Exception as e:
                self.append_result(f"\n❌ CSV save failed: {str(e)}\n", 'critical')
        
        if self.auto_save_html.get() and self.results:
            html_filename = f"abuseipdb_report_{timestamp}.html"
            try:
                self.generate_simple_html_report(html_filename)
                saved_files.append(f"HTML: {html_filename}")
            except Exception as e:
                self.append_result(f"\n❌ HTML save failed: {str(e)}\n", 'critical')
        
        if saved_files:
            self.append_result("\n" + "═" * 80 + "\n", 'header')
            self.append_result("💾 FILES AUTOMATICALLY SAVED:\n", 'success')
            for file_info in saved_files:
                self.append_result(f"  ✅ {file_info}\n", 'success')
            self.append_result("═" * 80 + "\n", 'header')
        
        messagebox.showinfo("Complete", f"Analysis complete! Checked {len(ips)} IPs.\n\nSaved files:\n" + "\n".join(saved_files) if saved_files else f"Analysis complete! Checked {len(ips)} IPs.")
    
    def check_ip(self, ip):
        """Check single IP against AbuseIPDB"""
        headers = {
            'Key': self.api_key.get(),
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
            
            # Process data
            all_categories = []
            if data.get('reports'):
                for report in data['reports']:
                    if report.get('categories'):
                        all_categories.extend(report['categories'])
                all_categories = list(set(all_categories))
            
            categories_text = ', '.join([ABUSE_CATEGORIES.get(c, f"Unknown ({c})") for c in all_categories]) if all_categories else "None"
            
            is_highly_reported = data['totalReports'] >= HIGHLY_REPORTED_THRESHOLD
            
            # Detect critical infrastructure
            isp = data.get('isp', '')
            domain = data.get('domain', '')
            is_critical_infra = False
            provider = None
            
            for prov, patterns in CRITICAL_INFRASTRUCTURE.items():
                for pattern in patterns:
                    if pattern.lower() in isp.lower() or pattern.lower() in domain.lower():
                        is_critical_infra = True
                        provider = prov
                        break
                if is_critical_infra:
                    break
            
            # Blocking recommendation
            score = data['abuseConfidenceScore']
            if is_critical_infra and score >= MODERATE_THRESHOLD:
                recommendation = '⚠️ MANUAL REVIEW REQUIRED'
                action = 'CONFIRM WITH CLIENT'
                requires_review = True
            elif score >= CRITICAL_THRESHOLD:
                recommendation = 'YES - BLOCK IMMEDIATELY'
                action = 'BLOCK NOW'
                requires_review = False
            elif score >= HIGH_THRESHOLD:
                recommendation = 'YES - BLOCK RECOMMENDED'
                action = 'BLOCK RECOMMENDED'
                requires_review = False
            elif score >= MODERATE_THRESHOLD:
                recommendation = 'REVIEW - INVESTIGATE'
                action = 'INVESTIGATE'
                requires_review = True
            else:
                recommendation = 'NO - SAFE TO ALLOW'
                action = 'ALLOW'
                requires_review = False
            
            return {
                'ip': ip,
                'abuse_confidence_score': score,
                'total_reports': data['totalReports'],
                'is_highly_reported': is_highly_reported,
                'country_code': data.get('countryCode', 'N/A'),
                'isp': isp or 'Unknown',
                'domain': domain or 'N/A',
                'is_critical_infrastructure': is_critical_infra,
                'infrastructure_provider': provider or 'N/A',
                'blocking_recommendation': recommendation,
                'recommended_action': action,
                'requires_manual_review': requires_review,
                'abuse_categories': categories_text
            }
        
        except Exception as e:
            self.append_result(f"  ✗ Error: {str(e)}\n", 'critical')
            return None
    
    def display_result(self, result):
        """Display result in text widget"""
        self.append_result(f"  Score: {result['abuse_confidence_score']}% | Reports: {result['total_reports']} | {result['country_code']} - {result['isp']}\n", 'info')
        
        if result['is_highly_reported']:
            self.append_result(f"  ⚠️ HIGHLY REPORTED\n", 'critical')
        
        if result['is_critical_infrastructure']:
            self.append_result(f"  🏢 CRITICAL INFRASTRUCTURE: {result['infrastructure_provider']}\n", 'warning')
        
        # Recommendation with color
        if 'BLOCK' in result['recommended_action']:
            tag = 'critical'
        elif result['requires_manual_review']:
            tag = 'warning'
        else:
            tag = 'success'
        
        self.append_result(f"  → {result['blocking_recommendation']}\n", tag)
        self.append_result(f"  → Action: {result['recommended_action']}\n\n", tag)
    
    def append_result(self, text, tag=None):
        """Append text to results widget"""
        self.results_text.insert(tk.END, text, tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def generate_simple_html_report(self, filename):
        """Generate simple HTML report"""
        total = len(self.results)
        block_now = len([r for r in self.results if 'BLOCK' in r.get('recommended_action', '') and not r.get('requires_manual_review')])
        manual_review = len([r for r in self.results if r.get('requires_manual_review')])
        microsoft_ips = [r for r in self.results if r.get('infrastructure_provider') == 'Microsoft' and r.get('abuse_confidence_score', 0) >= 25]
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AbuseIPDB Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box.red {{ background: #e74c3c; }}
        .stat-box.yellow {{ background: #f39c12; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .warning-box {{ background: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #3498db; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; }}
        .badge-safe {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AbuseIPDB Security Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
        
        if microsoft_ips:
            html += f"""
        <div class="warning-box">
            <h2 style="margin-top:0">⚠️ MICROSOFT INFRASTRUCTURE WARNING</h2>
            <p><strong>{len(microsoft_ips)} Microsoft IP(s) require CLIENT CONFIRMATION before blocking!</strong></p>
            <ul>
"""
            for ip in microsoft_ips:
                html += f'<li><strong>{ip["ip"]}</strong> - Score: {ip["abuse_confidence_score"]}% | Reports: {ip["total_reports"]}</li>'
            html += """
            </ul>
            <p><em>May affect: Office 365, Azure, Teams, Exchange Online</em></p>
        </div>
"""
        
        html += f"""
        <h2>Summary Statistics</h2>
        <div class="summary">
            <div class="stat-box">
                <div class="stat-number">{total}</div>
                <div>Total IPs</div>
            </div>
            <div class="stat-box red">
                <div class="stat-number">{block_now}</div>
                <div>Block Now</div>
            </div>
            <div class="stat-box yellow">
                <div class="stat-number">{manual_review}</div>
                <div>Manual Review</div>
            </div>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Score</th>
                <th>Reports</th>
                <th>Country</th>
                <th>ISP</th>
                <th>Infrastructure</th>
                <th>Recommendation</th>
            </tr>
"""
        
        for r in self.results:
            if r.get('abuse_confidence_score') == 'ERROR':
                continue
            score = r['abuse_confidence_score']
            badge_class = 'badge-critical' if score >= 75 else 'badge-warning' if score >= 25 else 'badge-safe'
            html += f"""
            <tr>
                <td><strong>{r['ip']}</strong></td>
                <td><span class="badge {badge_class}">{score}%</span></td>
                <td>{r['total_reports']}</td>
                <td>{r['country_code']}</td>
                <td>{r['isp'][:40]}...</td>
                <td>{r['infrastructure_provider']}</td>
                <td>{r['blocking_recommendation']}</td>
            </tr>
"""
        
        html += """
        </table>
        <p style="text-align: center; color: #6c757d; margin-top: 30px;">
            Report generated by AbuseIPDB Security Analyzer
        </p>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def append_result(self, text, tag=None):
        """Append text to results widget"""
        self.results_text.insert(tk.END, text, tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def export_results(self, format_type):
        """Export results to file"""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export. Run analysis first.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'csv':
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                initialfile=f"abuseipdb_analysis_{timestamp}.csv",
                filetypes=[("CSV files", "*.csv")]
            )
            if filename:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = list(self.results[0].keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.results)
                messagebox.showinfo("Success", f"Exported to {filename}")
        
        elif format_type == 'json':
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                initialfile=f"abuseipdb_analysis_{timestamp}.json",
                filetypes=[("JSON files", "*.json")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2)
                messagebox.showinfo("Success", f"Exported to {filename}")
        
        elif format_type == 'html':
            filename = filedialog.asksaveasfilename(
                defaultextension=".html",
                initialfile=f"abuseipdb_analysis_{timestamp}.html",
                filetypes=[("HTML files", "*.html")]
            )
            if filename:
                # Generate simple HTML report
                html = f"""<!DOCTYPE html>
<html>
<head><title>AbuseIPDB Analysis Report</title>
<style>
body {{font-family: Arial; background: #f5f5f5; padding: 20px;}}
.container {{max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;}}
h1 {{color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;}}
table {{width: 100%; border-collapse: collapse; margin: 20px 0;}}
th {{background: #3498db; color: white; padding: 12px; text-align: left;}}
td {{padding: 10px; border-bottom: 1px solid #ddd;}}
tr:hover {{background: #f8f9fa;}}
.critical {{background: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px;}}
.warning {{background: #f39c12; color: white; padding: 4px 8px; border-radius: 4px;}}
.safe {{background: #27ae60; color: white; padding: 4px 8px; border-radius: 4px;}}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ AbuseIPDB Security Analysis Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Results</h2>
<table>
<tr><th>IP</th><th>Score</th><th>Reports</th><th>Country</th><th>ISP</th><th>Infrastructure</th><th>Recommendation</th></tr>
"""
                for r in self.results:
                    badge_class = 'critical' if r['abuse_confidence_score'] >= 75 else 'warning' if r['abuse_confidence_score'] >= 25 else 'safe'
                    html += f"""<tr>
<td><strong>{r['ip']}</strong></td>
<td><span class="{badge_class}">{r['abuse_confidence_score']}%</span></td>
<td>{r['total_reports']}</td>
<td>{r['country_code']}</td>
<td>{r['isp']}</td>
<td>{r['infrastructure_provider']}</td>
<td>{r['blocking_recommendation']}</td>
</tr>"""
                
                html += """
</table>
</div>
</body>
</html>"""
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
                messagebox.showinfo("Success", f"Exported to {filename}")

def main():
    root = tk.Tk()
    app = AbuseIPDBApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
