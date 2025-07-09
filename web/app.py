# web/app.py

import streamlit as st
import sys
import os
import pandas as pd


script_dir = os.path.dirname(__file__)
parent_dir = os.path.join(script_dir, '..')
sys.path.append(parent_dir)

from src.recon_engine import run_all_scans
from src.report_generator import generate_html_report, save_pdf_report
from src.database import init_db, get_scan_history, get_scan_by_id

# Initialize the database on the first run
init_db()


def display_results(results):
    """
    Takes a results dictionary and renders it neatly on the Streamlit page.
    """
    st.subheader("🎯 Confirmed Vulnerabilities (from Nuclei)")
    if results.get('nuclei_findings'):
        findings_data = []
        for f in results['nuclei_findings']:
            info = f.get('info', {})
            findings_data.append({
                "Severity": info.get('severity', 'info').capitalize(),
                "Name": info.get('name', 'N/A'),
                "Description": info.get('description', 'N/A'),
                "Matched At": f.get('matched-at', 'N/A')
            })
        df = pd.DataFrame(findings_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No vulnerabilities were confirmed by Nuclei for this target.")

    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Subdomain Enumeration")
        if results.get('subdomains'):
            st.dataframe(pd.DataFrame(results['subdomains'], columns=["Found Subdomains"]))
        else:
            st.info("No subdomains were found.")

    with col2:
        st.subheader("Technology Stack")
        if results.get('technologies'):
            tech_list = []
            for tech_info in results['technologies']:
                for plugin, details in tech_info.get('plugins', {}).items():
                    version = ', '.join(details.get('version', []))
                    tech_list.append(f"{plugin} ({version})" if version else plugin)
            st.dataframe(pd.DataFrame(tech_list, columns=["Detected Technologies"]))
        else:
            st.info("No technologies were detected.")

    st.subheader("🧠 AI-Powered CVE Suggestions")
    if results.get('ai_suggestions'):
        st.markdown(results['ai_suggestions'])
    else:
        st.info("No AI suggestions are available for this scan.")
        
    st.subheader("Nmap Port Scan Results")
    if results.get('nmap_scan'):
        st.code(results['nmap_scan'])
    else:
        st.info("The Nmap scan did not return any results.")
        
    st.markdown("---")
    st.subheader("Download Report")
    
    
    html_report = generate_html_report(results)
    
    
    st.download_button(
        label="📥 Download HTML Report",
        data=html_report,
        file_name=f"{results.get('target', 'report')}_report.html",
        mime="text/html"
    )

    
    if st.button("Prepare PDF for Download"):
        with st.spinner("Generating PDF report, this may take a moment..."):
            output_dir = os.path.join(parent_dir, "output")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            pdf_path = os.path.join(output_dir, f"{results.get('target', 'report')}_report.pdf")
            
            # This is the slow part
            save_pdf_report(html_report, pdf_path)
            
            # Read the generated PDF into memory and store it in the session state
            with open(pdf_path, "rb") as f:
                st.session_state.pdf_data = f.read()
            
            # Store details for the download button
            st.session_state.pdf_filename = f"{results.get('target', 'report')}_report.pdf"
            st.session_state.pdf_ready = True

    # If the PDF has been prepared, show the actual download button
    if 'pdf_ready' in st.session_state and st.session_state.pdf_ready:
        st.download_button(
            label="✅ Click to Download PDF",
            data=st.session_state.pdf_data,
            file_name=st.session_state.pdf_filename,
            mime="application/octet-stream"
        )
        # Reset the flag after showing the button
        st.session_state.pdf_ready = False


# --- Main Streamlit App Layout ---
st.set_page_config(page_title="VulnSightAI", page_icon="🛡️", layout="wide")
st.title("🛡️ VulnSightAI: Vulnerability Assessment Dashboard")
st.markdown("---")

# --- Sidebar ---
st.sidebar.header("Scan Configuration")
target_domain = st.sidebar.text_input("Enter Target Domain:", placeholder="e.g., example.com")
start_scan_button = st.sidebar.button("🚀 Start New Scan")

st.sidebar.markdown("---")
st.sidebar.header("Scan History")

scan_history = get_scan_history()
# Create a mapping from a display string to the scan ID
history_options = {f"{row['target']} ({row['timestamp']})": row['id'] for row in scan_history}
# Add a placeholder for the selectbox
options_list = ["-- Select a past scan --"] + list(history_options.keys())
selected_history_display = st.sidebar.selectbox("View a past scan:", options=options_list)

# --- Main Content Area ---
st.header("Scan Results")

# Logic to decide what to show
if start_scan_button:
    if target_domain:
        with st.spinner(f"Performing full scan on {target_domain}... This may take several minutes."):
            scan_results = run_all_scans(target_domain)
            st.session_state['results_to_display'] = scan_results
            st.success("Scan Complete!")
    else:
        st.warning("Please enter a target domain to start a new scan.")

elif selected_history_display != "-- Select a past scan --":
    scan_id = history_options[selected_history_display]
    historical_results = get_scan_by_id(scan_id)
    if historical_results:
        st.session_state['results_to_display'] = historical_results
    else:
        st.error("Could not retrieve historical scan data.")
        st.session_state['results_to_display'] = None
else:
    # Clear the display area if nothing is selected
    st.session_state['results_to_display'] = None

# This part runs on every interaction. It displays whatever is in 'results_to_display'.
if 'results_to_display' in st.session_state and st.session_state['results_to_display']:
    display_results(st.session_state['results_to_display'])
elif not start_scan_button:
    st.info("Start a new scan or select a past scan from the history in the sidebar.")
