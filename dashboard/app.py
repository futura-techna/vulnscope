"""
VulnScope Dashboard - Streamlit Application
Enhanced with real-time progress, notifications, authentication, and interactive charts
"""

import streamlit as st
import requests
import pandas as pd
import altair as alt
from datetime import datetime, timedelta
import time
import json
from pathlib import Path

# Page config
st.set_page_config(
    page_title="VulnScope Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================
# SESSION STATE MANAGEMENT
# ============================================
if 'theme' not in st.session_state:
    st.session_state.theme = "dark"
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'scan_progress' not in st.session_state:
    st.session_state.scan_progress = 0


# ============================================
# THEME SYSTEM
# ============================================
def get_theme_css(theme):
    """Get CSS for the selected theme"""
    if theme == "dark":
        return """
        <style>
        .stApp {
            background-color: #1E1E1E;
            color: #E0E0E0;
        }
        .stMetric {
            background-color: #2D2D2D;
            padding: 15px;
            border-radius: 10px;
        }
        .stDataFrame {
            background-color: #2D2D2D;
        }
        div[data-testid="stMetricValue"] {
            color: #4CAF50;
        }
        .finding-critical {
            border-left: 5px solid #FF4444;
            padding: 10px;
            margin: 10px 0;
            background: #2D2D2D;
        }
        .finding-high {
            border-left: 5px solid #FF8800;
            padding: 10px;
            margin: 10px 0;
            background: #2D2D2D;
        }
        .sidebar-content {
            background-color: #2D2D2D;
        }
        </style>
        """
    else:
        return """
        <style>
        .stApp {
            background-color: #FFFFFF;
            color: #333333;
        }
        .stMetric {
            background-color: #F5F5F5;
            padding: 15px;
            border-radius: 10px;
        }
        .finding-critical {
            border-left: 5px solid #FF4444;
            padding: 10px;
            margin: 10px 0;
            background: #FFF5F5;
        }
        .finding-high {
            border-left: 5px solid #FF8800;
            padding: 10px;
            margin: 10px 0;
            background: #FFF8F0;
        }
        </style>
        """


# ============================================
# AUTHENTICATION SYSTEM
# ============================================
class AuthManager:
    """Simple session-based authentication"""
    
    USERS = {
        "admin": {"password": "admin123", "role": "admin"},
        "security": {"password": "sec123", "role": "security_engineer"},
        "viewer": {"password": "viewer123", "role": "viewer"}
    }
    
    @classmethod
    def login(cls, username, password):
        """Authenticate user"""
        if username in cls.USERS:
            if cls.USERS[username]["password"] == password:
                return {
                    "username": username,
                    "role": cls.USERS[username]["role"]
                }
        return None
    
    @classmethod
    def logout(cls):
        """Logout user"""
        st.session_state.authenticated = False
        st.session_state.user = None


def login_page():
    """Login page"""
    st.title("🔐 VulnScope Login")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                user = AuthManager.login(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Invalid username or password")
        
        st.info("Demo credentials: admin / admin123")


# ============================================
# NOTIFICATION SYSTEM
# ============================================
class NotificationManager:
    """Manage dashboard notifications"""
    
    @staticmethod
    def show_critical_alert(count):
        """Show critical vulnerability alert"""
        if count > 0:
            st.error(f"🚨 CRITICAL ALERT: {count} critical vulnerabilities detected!")
            st.markdown("""
            > **Action Required**: Immediate attention needed for critical security issues.
            > Contact your security team immediately.
            """)
    
    @staticmethod
    def show_scan_complete(scan_name):
        """Show scan completion notification"""
        st.success(f"✅ Scan '{scan_name}' completed successfully!")
    
    @staticmethod
    def show_info(message):
        """Show info notification"""
        st.info(message)
    
    @staticmethod
    def show_warning(message):
        """Show warning notification"""
        st.warning(message)


# ============================================
# REAL-TIME PROGRESS TRACKER
# ============================================
class ProgressTracker:
    """Track and display scan progress in real-time"""
    
    @staticmethod
    def create_progress_bar():
        """Create a progress bar"""
        return st.progress(0)
    
    @staticmethod
    def update_progress(progress_bar, current, total, message=""):
        """Update progress bar"""
        if total > 0:
            percentage = int((current / total) * 100)
            progress_bar.progress(percentage)
            if message:
                st.caption(f"{message}: {percentage}%")
    
    @staticmethod
    def simulate_scan_progress():
        """Simulate scan progress for demo"""
        progress_bar = st.progress(0)
        status_text = st.empty()
        metrics_row = st.columns(4)
        
        endpoints = metrics_row[0].empty()
        vulnerabilities = metrics_row[1].empty()
        critical = metrics_row[2].empty()
        high = metrics_row[3].empty()
        
        for i in range(100):
            time.sleep(0.03)
            progress_bar.progress(i + 1)
            status_text.text(f"Scan progress: {i + 1}%")
            
            # Simulate metrics
            endpoints.metric("Endpoints", i * 2)
            vulnerabilities.metric("Vulnerabilities", max(0, i - 80))
            critical.metric("Critical", max(0, (i - 90) * 2))
            high.metric("High", max(0, i - 70))
        
        return progress_bar


# ============================================
# INTERACTIVE CHARTS
# ============================================
def create_severity_chart(findings_data, theme):
    """Create interactive severity distribution chart"""
    severity_counts = {}
    for f in findings_data:
        severity_counts[f["Severity"]] = severity_counts.get(f["Severity"], 0) + 1
    
    df = pd.DataFrame(list(severity_counts.items()), columns=["Severity", "Count"])
    
    colors = {
        "Critical": "#FF4444",
        "High": "#FF8800",
        "Medium": "#FFCC00",
        "Low": "#44AA44",
        "Info": "#4488AA"
    }
    
    chart = alt.Chart(df).mark_bar().encode(
        x=alt.X("Severity:O", sort=["Critical", "High", "Medium", "Low", "Info"], axis=alt.Axis(labelAngle=0)),
        y=alt.Y("Count:Q"),
        color=alt.Color("Severity:O", scale=alt.Scale(
            domain=list(colors.keys()),
            range=list(colors.values())
        ), legend=None),
        tooltip=["Severity", "Count"]
    ).properties(
        title="Findings by Severity",
        height=300
    ).interactive()
    
    return chart


def create_trend_chart(historical_data, theme):
    """Create vulnerability trend over time chart"""
    df = pd.DataFrame(historical_data)
    
    chart = alt.Chart(df).mark_line(point=True).encode(
        x=alt.X("Week:O", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("Count:Q"),
        color=alt.Color("Severity:O"),
        tooltip=["Week", "Severity", "Count"]
    ).properties(
        title="Vulnerability Trends Over Time",
        height=300
    ).interactive()
    
    return chart


def create_correlation_chart(findings_data):
    """Create correlation heatmap for vulnerabilities"""
    # Group by type and severity
    data = []
    for f in findings_data:
        data.append({"Type": f["Type"], "Severity": f["Severity"]})
    
    df = pd.DataFrame(data)
    if df.empty:
        return None
    
    # Create pivot table
    pivot = df.groupby(["Type", "Severity"]).size().reset_index(name="Count")
    
    chart = alt.Chart(pivot).mark_rect().encode(
        x="Type:O",
        y="Severity:O",
        color=alt.Color("Count:Q", scale=alt.Scale(scheme="blues")),
        tooltip=["Type", "Severity", "Count"]
    ).properties(
        title="Vulnerability Type vs Severity",
        height=250
    )
    
    return chart


# ============================================
# MAIN DASHBOARD
# ============================================
def main():
    """Main dashboard application"""
    
    # Check authentication
    if not st.session_state.authenticated:
        login_page()
        return
    
    # Sidebar
    st.sidebar.title("🛡️ VulnScope")
    st.sidebar.image("https://via.placeholder.com/150x50?text=VulnScope", width=150)
    
    # Navigation
    st.sidebar.subheader("📍 Navigation")
    page = st.sidebar.radio("Go to", [
        "Dashboard", "Targets", "Scans", "Findings", "Compliance", "Reports", "Settings"
    ])
    
    # User info
    st.sidebar.divider()
    st.sidebar.subheader("👤 User")
    st.sidebar.write(f"**{st.session_state.user['username']}**")
    st.sidebar.write(f"Role: {st.session_state.user['role']}")
    if st.sidebar.button("Logout"):
        AuthManager.logout()
        st.rerun()
    
    # Theme selector
    st.sidebar.divider()
    st.sidebar.subheader("🎨 Appearance")
    theme = st.sidebar.selectbox(
        "Theme",
        ["Light", "Dark"],
        index=1 if st.session_state.theme == "dark" else 0,
        key="theme_selector"
    )
    st.session_state.theme = theme.lower()
    st.markdown(get_theme_css(st.session_state.theme), unsafe_allow_html=True)
    
    # API Base URL
    API_URL = "http://localhost:8000/api/v1"
    
    # Sample data
    scans_data = [
        {"Name": "Full Scan - Production", "Target": "app.example.com", "Status": "Completed", "Findings": 23, "Date": "2024-01-15"},
        {"Name": "Quick Scan - Dev", "Target": "dev.example.com", "Status": "Completed", "Findings": 5, "Date": "2024-01-14"},
        {"Name": "API Security Scan", "Target": "api.example.com", "Status": "Running", "Findings": 8, "Date": "2024-01-14"},
        {"Name": "Auth Test", "Target": "auth.example.com", "Status": "Completed", "Findings": 12, "Date": "2024-01-13"},
    ]
    
    targets_data = [
        {"Name": "Production App", "URL": "https://app.example.com", "Type": "Web App", "Last Scan": "2024-01-15"},
        {"Name": "Dev Environment", "URL": "https://dev.example.com", "Type": "Web App", "Last Scan": "2024-01-14"},
        {"Name": "API Gateway", "URL": "https://api.example.com", "Type": "REST API", "Last Scan": "2024-01-13"},
    ]
    
    findings_data = [
        {"ID": "VULN-001", "Title": "SQL Injection in /api/users", "Severity": "Critical", "Type": "SQL Injection", "Target": "app.example.com", "Status": "Open"},
        {"ID": "VULN-002", "Title": "XSS in search parameter", "Severity": "High", "Type": "XSS", "Target": "app.example.com", "Status": "Open"},
        {"ID": "VULN-003", "Title": "SSRF in URL parameter", "Severity": "High", "Type": "SSRF", "Target": "api.example.com", "Status": "In Progress"},
        {"ID": "VULN-004", "Title": "IDOR in /user/profile", "Severity": "Medium", "Type": "IDOR", "Target": "app.example.com", "Status": "Open"},
        {"ID": "VULN-005", "Title": "CSRF missing token", "Severity": "Medium", "Type": "CSRF", "Target": "app.example.com", "Status": "Open"},
        {"ID": "VULN-006", "Title": "XXE in XML parser", "Severity": "Critical", "Type": "XXE", "Target": "api.example.com", "Status": "Open"},
    ]
    
    # Severity colors
    SEVERITY_COLORS = {
        "Critical": "#FF4444",
        "High": "#FF8800",
        "Medium": "#FFCC00",
        "Low": "#44AA44",
        "Info": "#4488AA"
    }
    
    # ============================================
    # DASHBOARD PAGE
    # ============================================
    if page == "Dashboard":
        st.title("🛡️ VulnScope Dashboard")
        
        # Notifications for critical findings
        critical_count = len([f for f in findings_data if f["Severity"] == "Critical"])
        NotificationManager.show_critical_alert(critical_count)
        
        # Stats metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Scans", "150", "+12")
        with col2:
            st.metric("Active Scans", "3", "0")
        with col3:
            st.metric("Critical Findings", critical_count, "-3")
        with col4:
            st.metric("High Findings", "45", "+5")
        
        st.divider()
        
        # Interactive Analysis Section
        st.subheader("📊 Interactive Analysis")
        
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            selected_severities = st.multiselect(
                "Filter by Severity",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with col2:
            selected_targets = st.multiselect(
                "Filter by Target",
                list(set(f["Target"] for f in findings_data)),
                default=list(set(f["Target"] for f in findings_data))
            )
        
        # Filter data
        filtered_findings = [
            f for f in findings_data 
            if f["Severity"] in selected_severities and f["Target"] in selected_targets
        ]
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Findings by Severity")
            if filtered_findings:
                chart = create_severity_chart(filtered_findings, st.session_state.theme)
                st.altair_chart(chart, use_container_width=True)
            else:
                st.info("No findings match the selected filters")
        
        with col2:
            st.subheader("Vulnerability Trends")
            time_data = {"Week": ["Week 1", "Week 2", "Week 3", "Week 4"], 
                        "Count": [15, 23, 18, 25],
                        "Severity": ["Medium", "High", "Medium", "High"]}
            df = pd.DataFrame(time_data)
            chart = alt.Chart(df).mark_bar().encode(
                x=alt.X("Week:O", axis=alt.Axis(labelAngle=0)),
                y="Count:Q",
                color=alt.Color("Severity:O"),
                tooltip=["Week", "Count"]
            ).properties(title="Vulnerabilities Over Time", height=300)
            st.altair_chart(chart, use_container_width=True)
        
        # Correlation heatmap
        with st.expander("📈 Vulnerability Correlation Analysis"):
            corr_chart = create_correlation_chart(filtered_findings)
            if corr_chart:
                st.altair_chart(corr_chart, use_container_width=True)
        
        # Recent scans
        st.divider()
        st.subheader("📋 Recent Scans")
        df_scans = pd.DataFrame(scans_data)
        st.table(df_scans)
    
    # ============================================
    # TARGETS PAGE
    # ============================================
    elif page == "Targets":
        st.title("🎯 Targets")
        
        # Create new target form
        st.subheader("➕ Add New Target")
        
        col1, col2 = st.columns(2)
        
        with col1:
            target_name = st.text_input("Target Name", "My Application")
            target_url = st.text_input("Target URL", "https://example.com")
        with col2:
            target_type = st.selectbox("Type", ["Web App", "REST API", "GraphQL API", "Mobile App"])
            target_description = st.text_input("Description", "Security assessment target")
        
        tags = st.text_input("Tags (comma separated)", "production, critical")
        
        # Authentication section
        st.subheader("🔐 Authentication (Optional)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            auth_type = st.selectbox("Auth Type", ["None", "Basic", "Bearer Token", "API Key", "OAuth2"])
        with col2:
            auth_value = st.text_input("Auth Value", type="password")
        
        if st.button("➕ Add Target"):
            st.success(f"✅ Target '{target_name}' added successfully! (Demo mode)")
        
        st.divider()
        
        st.subheader("📋 Existing Targets")
        df_targets = pd.DataFrame(targets_data)
        st.table(df_targets)
    
    # ============================================
    # SCANS PAGE
    # ============================================
    elif page == "Scans":
        st.title("🔍 Scans")
        
        st.subheader("➕ Create New Scan")
        
        col1, col2 = st.columns(2)
        
        with col1:
            scan_name = st.text_input("Scan Name", "New Security Scan")
            target_url = st.text_input("Target URL", "https://app.example.com")
        with col2:
            scan_type = st.selectbox("Scan Type", ["full", "quick", "api", "auth"])
            scan_description = st.text_input("Description", "Security vulnerability scan")
        
        st.subheader("⚙️ Scan Options")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            enable_crawler = st.checkbox("Enable Crawler", value=True)
        with col2:
            enable_dast = st.checkbox("Enable DAST", value=True)
        with col3:
            enable_fuzzer = st.checkbox("Enable Fuzzer", value=False)
        with col4:
            enable_openapi = st.checkbox("Import OpenAPI", value=False)
        
        # Advanced options
        with st.expander("🔧 Advanced Options"):
            col1, col2, col3 = st.columns(3)
            with col1:
                max_concurrent = st.slider("Max Concurrent Requests", 1, 100, 10)
            with col2:
                timeout = st.slider("Request Timeout (s)", 5, 120, 30)
            with col3:
                recursive_depth = st.slider("Recursive Scan Depth", 1, 5, 3)
        
        # Real-time progress
        if st.button("🚀 Start Scan"):
            with st.spinner("Initializing scan..."):
                progress_tracker = ProgressTracker()
                progress_tracker.simulate_scan_progress()
                NotificationManager.show_scan_complete(scan_name)
            
            # Show results
            st.subheader("📊 Scan Results")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Endpoints Found", "150")
            with col2:
                st.metric("Vulnerabilities", "12")
            with col3:
                st.metric("Critical", "3")
            with col4:
                st.metric("High", "5")
        
        st.divider()
        
        st.subheader("📋 Scan History")
        st.dataframe(pd.DataFrame(scans_data), use_container_width=True)
    
    # ============================================
    # FINDINGS PAGE
    # ============================================
    elif page == "Findings":
        st.title("⚠️ Findings")
        
        # Critical findings notification
        critical_findings = [f for f in findings_data if f["Severity"] == "Critical"]
        if critical_findings:
            with st.expander(f"🚨 Critical Findings ({len(critical_findings)})", expanded=True):
                for f in critical_findings:
                    st.markdown(f"""
                    <div class="finding-critical">
                        <strong>{f['ID']}</strong>: {f['Title']} - {f['Target']}
                    </div>
                    """, unsafe_allow_html=True)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            severity_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"])
        with col2:
            vuln_type = st.multiselect("Type", ["SQL Injection", "XSS", "SSRF", "IDOR", "CSRF"])
        with col3:
            status = st.selectbox("Status", ["All", "Open", "In Progress", "Resolved", "False Positive"])
        
        # Apply filters
        filtered = findings_data
        if severity_filter:
            filtered = [f for f in filtered if f["Severity"] in severity_filter]
        if vuln_type:
            filtered = [f for f in filtered if f["Type"] in vuln_type]
        if status != "All":
            filtered = [f for f in filtered if f["Status"] == status]
        
        # Display findings
        st.subheader(f"Findings ({len(filtered)})")
        df_findings = pd.DataFrame(filtered)
        
        # Color-coded table
        def highlight_severity(val):
            color = SEVERITY_COLORS.get(val, '')
            return f'background-color: {color}; color: white' if color else ''
        
        st.dataframe(
            df_findings.style.applymap(highlight_severity, subset=['Severity']),
            use_container_width=True
        )
        
        # Chart
        st.subheader("Findings by Type")
        vuln_types = {}
        for f in filtered:
            t = f["Type"]
            vuln_types[t] = vuln_types.get(t, 0) + 1
        
        df = pd.DataFrame(list(vuln_types.items()), columns=["Type", "Count"])
        chart = alt.Chart(df).mark_bar().encode(
            x=alt.X("Type:O", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Count:Q"),
            tooltip=["Type", "Count"]
        ).properties(title="Findings by Type", height=300)
        st.altair_chart(chart, use_container_width=True)
    
    # ============================================
    # COMPLIANCE PAGE
    # ============================================
    elif page == "Compliance":
        st.title("📜 Compliance")
        
        # Compliance overview
        col1, col2, col3, col4, col5 = st.columns(5)
        
        standards = [
            ("PCI-DSS", "95%", "✅"),
            ("NIS2", "78%", "⚠️"),
            ("SOC2", "92%", "✅"),
            ("HIPAA", "88%", "⚠️"),
            ("ISO27001", "85%", "⚠️"),
        ]
        
        for i, (name, score, status) in enumerate(standards):
            with [col1, col2, col3, col4, col5][i]:
                st.metric(name, score, status)
        
        st.subheader("Compliance by Category")
        compliance_data = {
            "Access Control": 92,
            "Encryption": 88,
            "Monitoring": 95,
            "Incident Response": 78,
            "Vendor Management": 85,
        }
        
        df = pd.DataFrame(list(compliance_data.items()), columns=["Category", "Score"])
        chart = alt.Chart(df).mark_bar().encode(
            x=alt.X("Category:O", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Score:Q"),
            color=alt.Color("Score:Q", scale=alt.Scale(domain=[0, 100], range=["red", "yellow", "green"])),
            tooltip=["Category", "Score"]
        ).properties(title="Compliance by Category", height=300)
        st.altair_chart(chart, use_container_width=True)
    
    # ============================================
    # REPORTS PAGE
    # ============================================
    elif page == "Reports":
        st.title("📄 Reports")
        
        scan_name = st.selectbox("Select Scan", [
            "Full Scan - Production", 
            "Quick Scan - Dev", 
            "API Security Scan",
            "Auth Test"
        ])
        
        scan_id = scan_name.lower().replace(" ", "-")
        
        st.subheader("📥 Download Reports")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        json_content = f'{{"report": {{"title": "{scan_name}", "findings": []}}}}'
        with col1:
            st.download_button(
                label="📄 JSON",
                data=json_content,
                file_name=f"vulnscope_report_{scan_id}.json",
                mime="application/json"
            )
        
        html_content = f"<html><body><h1>VulnScope Report - {scan_name}</h1></body></html>"
        with col2:
            st.download_button(
                label="📄 HTML",
                data=html_content,
                file_name=f"vulnscope_report_{scan_id}.html",
                mime="text/html"
            )
        
        csv_content = "ID,Title,Severity\n1,SQL Injection,Critical"
        with col3:
            st.download_button(
                label="📄 CSV",
                data=csv_content,
                file_name=f"vulnscope_report_{scan_id}.csv",
                mime="text/csv"
            )
        
        sarif_content = '{"$schema": "sarif", "runs": []}'
        with col4:
            st.download_button(
                label="📄 SARIF",
                data=sarif_content,
                file_name=f"vulnscope_report_{scan_id}.sarif",
                mime="application/json"
            )
        
        # PDF Export (requires reportlab)
        with col5:
            st.download_button(
                label="📄 PDF",
                data="PDF export requires additional configuration",
                file_name=f"vulnscope_report_{scan_id}.pdf",
                disabled=True
            )
        
        # Executive Report section
        st.divider()
        st.subheader("📊 Executive Report")
        
        if st.button("Generate Executive Report"):
            with st.spinner("Generating executive report..."):
                time.sleep(1)
                
            # Show executive summary
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Risk Score", "72/100", "High")
            with col2:
                st.metric("Critical Issues", "3", "-1")
            with col3:
                st.metric("Remediation Time", "~2 days")
            
            st.success("Executive report generated successfully!")
        
        # Report history
        st.divider()
        st.subheader("📋 Report History")
        reports = [
            {"Name": "Full Scan Report", "Format": "HTML", "Date": "2024-01-15", "Size": "2.3 MB"},
            {"Name": "Executive Summary", "Format": "PDF", "Date": "2024-01-14", "Size": "450 KB"},
            {"Name": "Compliance Report - PCI", "Format": "JSON", "Date": "2024-01-13", "Size": "120 KB"},
        ]
        
        st.table(pd.DataFrame(reports))
    
    # ============================================
    # SETTINGS PAGE
    # ============================================
    elif page == "Settings":
        st.title("⚙️ Settings")
        
        # General settings
        st.subheader("General")
        
        col1, col2 = st.columns(2)
        
        with col1:
            api_url = st.text_input("API URL", value=API_URL)
        with col2:
            api_key = st.text_input("API Key", type="password")
        
        # Scanner settings
        st.subheader("Scanner")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            max_concurrent = st.number_input("Max Concurrent Requests", value=10)
        with col2:
            timeout = st.number_input("Request Timeout (seconds)", value=30)
        with col3:
            rate_limit = st.number_input("Rate Limit (req/sec)", value=100)
        
        # Notification settings
        st.subheader("Notifications")
        
        col1, col2 = st.columns(2)
        
        with col1:
            email_notif = st.checkbox("Email notifications for critical findings", value=True)
        with col2:
            slack_integration = st.checkbox("Slack integration", value=False)
        
        # Theme settings
        st.subheader("Dashboard Theme")
        
        col1, col2 = st.columns(2)
        with col1:
            default_theme = st.selectbox("Default Theme", ["Light", "Dark"])
        with col2:
            auto_refresh = st.checkbox("Auto-refresh dashboard", value=False)
        
        # Save button
        if st.button("💾 Save Settings"):
            st.success("Settings saved successfully!")


# ============================================
# RUN DASHBOARD
# ============================================
if __name__ == "__main__":
    main()
