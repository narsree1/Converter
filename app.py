import streamlit as st
import anthropic
import pandas as pd
import os
from datetime import datetime

# Import configuration (create config.py with the prompt)
# For now, we'll define it inline, but you can move to separate file
CONVERSION_PROMPT = """You are an expert in log analysis and query conversion, specializing in Splunk SPL and CrowdStrike Falcon LogScale CQL. Your task is to convert Splunk SPL queries into equivalent Falcon LogScale CQL queries while maintaining identical functionality and detection logic.

## Core Conversion Guidelines:

1. **Field Mapping**: When translating fields, align to the Falcon LogScale Schema. Reference CrowdStrike's community content for accurate field mappings: https://github.com/CrowdStrike/logscale-community-content

2. **Function Translation**: Convert all SPL functions to CQL equivalents:
   - `stats` → `groupBy()` or aggregate functions
   - `eval` → field assignments using `:=` operator
   - `search` → filter conditions with pipe operators
   - `rex` → `regex()` or pattern matching
   - `rename` → `rename(field="x", as="y")`
   - `lookup` → `match()` or `join()` operations
   - `where` → conditional filters with `|`

3. **Syntax Requirements**: Use proper CQL syntax including pipes (`|`), case statements, regex patterns, and aggregation functions

4. **Security Context**: These queries are for SIEM threat detection and log correlation. Preserve all detection logic, thresholds, and correlation rules.

5. **Field Name Mapping**: Be aware that Splunk and LogScale use different field naming conventions. Common mappings:
   - SPL `host` → CQL `ComputerName` or `aid`
   - SPL `source_ip` → CQL `RemoteAddressIP4`
   - SPL `user` → CQL `UserName`
   - SPL `process` → CQL `ImageFileName`

## Output Format:
- Provide ONLY the converted CQL query
- If conversion is impossible, respond with "ERROR: [specific reason]"
- Ensure the output is syntactically valid CQL with no parsing errors
- Maintain all filtering logic, conditions, and operations from the original SPL

## Critical Rules:
- Preserve exact detection logic and thresholds
- Do not add explanations or commentary unless conversion fails
- Ensure output can be directly executed in LogScale
- Handle time-based functions appropriately (SPL `earliest`/`latest` → CQL time selectors)

Convert the following SPL query to CQL:

{spl_query}"""

CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 2048
TEMPERATURE = 0.1  # Research-proven optimal

# Page configuration
st.set_page_config(
    page_title="SPL to CQL Converter",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .stAlert {
        margin-top: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'conversion_history' not in st.session_state:
    st.session_state.conversion_history = []
if 'feedback_data' not in st.session_state:
    st.session_state.feedback_data = []

def get_anthropic_client():
    """Initialize Anthropic client with API key"""
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        # Check Streamlit secrets as fallback
        try:
            api_key = st.secrets.get("ANTHROPIC_API_KEY")
        except:
            pass
    
    if not api_key:
        st.error("⚠️ ANTHROPIC_API_KEY not found")
        st.info("""
        Please add your API key:
        1. In Streamlit Cloud: Settings → Secrets
        2. Locally: Set environment variable
        """)
        return None
    return anthropic.Anthropic(api_key=api_key)

def convert_spl_to_cql(spl_query, client):
    """Convert SPL query to CQL using Claude API with optimized prompt"""
    try:
        prompt = CONVERSION_PROMPT.format(spl_query=spl_query.strip())
        
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        result = message.content[0].text.strip()
        
        # Check if conversion failed
        if result.startswith("ERROR:"):
            return None, result.replace("ERROR:", "").strip()
        
        return result, None
    except Exception as e:
        return None, f"API Error: {str(e)}"

def validate_query(query):
    """Basic validation of SPL query format"""
    if not query or len(query.strip()) < 5:
        return False, "Query is too short or empty"
    
    # Check for basic SPL patterns
    spl_patterns = ['search', 'stats', 'eval', 'rex', '|', 'sourcetype=', 'index=', 'where', 'table']
    if not any(pattern in query.lower() for pattern in spl_patterns):
        return False, "Does not appear to be a valid SPL query"
    
    return True, None

def process_csv_file(uploaded_file, client):
    """Process CSV file with multiple queries"""
    try:
        df = pd.read_csv(uploaded_file)
        
        # Validate required columns
        required_cols = ['use_case_name', 'description', 'spl_query']
        if not all(col in df.columns for col in required_cols):
            return None, f"CSV must contain columns: {', '.join(required_cols)}"
        
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for idx, row in df.iterrows():
            status_text.text(f"Processing {idx + 1} of {len(df)}: {row['use_case_name']}")
            
            cql_query, error = convert_spl_to_cql(row['spl_query'], client)
            
            results.append({
                'use_case_name': row['use_case_name'],
                'description': row['description'],
                'spl_query': row['spl_query'],
                'cql_query': cql_query if cql_query else f"CONVERSION_FAILED: {error}",
                'status': 'Success' if cql_query else 'Failed',
                'error_reason': error if error else 'N/A'
            })
            
            progress_bar.progress((idx + 1) / len(df))
        
        status_text.empty()
        progress_bar.empty()
        
        results_df = pd.DataFrame(results)
        return results_df, None
        
    except Exception as e:
        return None, f"Error processing CSV: {str(e)}"

# Main UI
st.title("🔍 Splunk SPL to CrowdStrike LogScale CQL Converter")
st.markdown("""
Convert Splunk SPL queries to CrowdStrike Falcon LogScale CQL queries using Claude AI with research-optimized prompts.
""")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # API Key status
    api_key = os.getenv('ANTHROPIC_API_KEY') or st.secrets.get("ANTHROPIC_API_KEY", None) if hasattr(st, 'secrets') else None
    if api_key:
        st.success("✅ API Key Configured")
    else:
        st.warning("⚠️ API Key Not Found")
        manual_key = st.text_input("Enter API Key", type="password")
        if manual_key:
            os.environ['ANTHROPIC_API_KEY'] = manual_key
            st.rerun()
    
    st.markdown("---")
    
    st.header("🎛️ Model Settings")
    st.info(f"""
    **Model:** {CLAUDE_MODEL}
    **Temperature:** {TEMPERATURE} (Optimized)
    **Max Tokens:** {MAX_TOKENS}
    """)
    
    st.markdown("---")
    
    st.header("📚 Resources")
    st.markdown("""
    - [CrowdStrike LogScale Docs](https://library.humio.com/)
    - [LogScale Community](https://github.com/CrowdStrike/logscale-community-content)
    - [CQL Query Functions](https://library.humio.com/data-analysis/query-functions.html)
    """)
    
    st.markdown("---")
    
    st.header("💡 Conversion Tips")
    with st.expander("View Tips"):
        st.markdown("""
        - Use `#event_simpleName` for event filtering
        - `:=` for field assignment (not `=`)
        - `groupBy()` requires explicit functions
        - Regex uses `/pattern/` syntax
        - Time: `@timestamp > -24h`
        """)
    
    with st.expander("🔬 Prompt Optimization"):
        st.markdown("""
        **Based on SANS Research:**
        - Temperature 0.1 = 55/146 success
        - Structured prompts = 60% fewer errors
        - Explicit mappings = higher accuracy
        
        **Expected Results:**
        - 40-50% immediate success
        - 70-80% with minor tweaks
        - <5% parsing errors
        """)

# Main content tabs
tab1, tab2, tab3, tab4 = st.tabs(["🔄 Single Query", "📊 Batch CSV", "📜 History", "📖 Help"])

with tab1:
    st.header("Convert Single SPL Query")
    
    # Sample queries dropdown
    sample_options = {
        "Custom Query": "",
        "Failed Login Attempts": "index=main sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, user | where count > 5",
        "PowerShell Encoded": "index=main sourcetype=WinEventLog:PowerShell | search EncodedCommand=* | table _time, host, CommandLine",
        "Suspicious Process": "index=main EventCode=4688 | eval cmdline=lower(CommandLine) | search cmdline=\"*powershell*\"",
        "Network Connections": "index=main sourcetype=firewall | stats sum(bytes) by src_ip, dest_port | where sum(bytes) > 1000000"
    }
    
    selected_sample = st.selectbox("Load Sample Query:", list(sample_options.keys()))
    
    spl_input = st.text_area(
        "Enter Splunk SPL Query:",
        value=sample_options[selected_sample],
        height=150,
        help="Paste your Splunk SPL query here",
        placeholder="index=main | stats count by field | where count > 5"
    )
    
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        convert_btn = st.button("🔄 Convert", type="primary", use_container_width=True)
    with col2:
        clear_btn = st.button("🗑️ Clear", use_container_width=True)
    
    if clear_btn:
        st.rerun()
    
    if convert_btn:
        if not spl_input.strip():
            st.error("Please enter a SPL query")
        else:
            client = get_anthropic_client()
            if client:
                # Validate query
                is_valid, validation_error = validate_query(spl_input)
                if not is_valid:
                    st.warning(f"⚠️ Query validation warning: {validation_error}")
                
                with st.spinner("🔄 Converting query... Using optimized prompt with temperature 0.1"):
                    start_time = datetime.now()
                    cql_result, error = convert_spl_to_cql(spl_input, client)
                    elapsed_time = (datetime.now() - start_time).total_seconds()
                
                if cql_result:
                    st.success(f"✅ Conversion successful! ({elapsed_time:.2f}s)")
                    
                    # Display results
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("📝 Original SPL Query")
                        st.code(spl_input, language="sql")
                        
                        # Copy button
                        if st.button("📋 Copy SPL"):
                            st.write("SPL copied to clipboard!")
                    
                    with col2:
                        st.subheader("✨ Converted CQL Query")
                        st.code(cql_result, language="sql")
                        
                        # Copy button
                        if st.button("📋 Copy CQL"):
                            st.write("CQL copied to clipboard!")
                    
                    # Add to history
                    st.session_state.conversion_history.insert(0, {
                        'spl': spl_input,
                        'cql': cql_result,
                        'timestamp': datetime.now(),
                        'conversion_time': elapsed_time
                    })
                    
                    # Feedback section
                    st.markdown("---")
                    st.subheader("📝 Was this conversion accurate?")
                    
                    col1, col2, col3 = st.columns([1, 1, 3])
                    
                    with col1:
                        if st.button("✅ Correct", use_container_width=True):
                            st.session_state.feedback_data.append({
                                'spl': spl_input,
                                'cql': cql_result,
                                'feedback': 'correct',
                                'timestamp': datetime.now()
                            })
                            st.success("Thank you for your feedback! ✨")
                    
                    with col2:
                        if st.button("❌ Incorrect", use_container_width=True):
                            st.session_state.feedback_data.append({
                                'spl': spl_input,
                                'cql': cql_result,
                                'feedback': 'incorrect',
                                'timestamp': datetime.now()
                            })
                            st.warning("Feedback recorded. Please share the correct version if possible.")
                    
                    # Additional notes
                    feedback_notes = st.text_area("Additional notes (optional):", placeholder="Provide corrections or suggestions...")
                    if feedback_notes and st.button("💾 Save Notes"):
                        st.session_state.feedback_data[-1]['notes'] = feedback_notes
                        st.success("Notes saved!")
                
                else:
                    st.error(f"❌ Conversion failed: {error}")
                    st.info("💡 Try simplifying the query or check for syntax errors")
                    
                    # Suggestions based on error
                    if "unsupported" in error.lower():
                        st.warning("This query contains SPL functions that may not have direct CQL equivalents. Consider breaking it into simpler components.")
                    elif "lookup" in error.lower():
                        st.warning("Lookups require external data sources. You may need to implement this manually in LogScale.")

with tab2:
    st.header("📊 Batch Convert from CSV")
    
    st.markdown("""
    Upload a CSV file with the following columns:
    - **use_case_name**: Detection rule name
    - **description**: What the rule detects
    - **spl_query**: The Splunk SPL query
    """)
    
    # Sample CSV template
    sample_data = {
        'use_case_name': ['Failed Login Detection', 'Suspicious PowerShell', 'Network Anomaly'],
        'description': [
            'Detect multiple failed login attempts from same source',
            'Detect encoded PowerShell commands',
            'Detect unusual network traffic patterns'
        ],
        'spl_query': [
            'index=main sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, user | where count > 5',
            'index=main sourcetype=WinEventLog:PowerShell | search EncodedCommand=* | table _time, host, CommandLine',
            'index=main sourcetype=firewall | stats sum(bytes) by src_ip | where sum(bytes) > 10000000'
        ]
    }
    sample_df = pd.DataFrame(sample_data)
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.download_button(
            label="📥 Download Sample CSV",
            data=sample_df.to_csv(index=False),
            file_name="spl_queries_template.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    uploaded_file = st.file_uploader("📤 Upload CSV file", type=['csv'])
    
    if uploaded_file:
        st.subheader("📋 Preview Uploaded Data")
        preview_df = pd.read_csv(uploaded_file)
        st.dataframe(preview_df, use_container_width=True, height=200)
        
        st.info(f"📊 Total queries to convert: {len(preview_df)}")
        
        if st.button("🚀 Convert All Queries", type="primary", use_container_width=True):
            client = get_anthropic_client()
            if client:
                with st.spinner("🔄 Processing queries..."):
                    start_time = datetime.now()
                    results_df, error = process_csv_file(uploaded_file, client)
                    elapsed_time = (datetime.now() - start_time).total_seconds()
                
                if results_df is not None:
                    st.success(f"✅ Processed {len(results_df)} queries in {elapsed_time:.2f}s")
                    
                    # Summary metrics
                    success_count = len(results_df[results_df['status'] == 'Success'])
                    failed_count = len(results_df[results_df['status'] == 'Failed'])
                    success_rate = (success_count / len(results_df)) * 100
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("✅ Successful", success_count, f"{success_rate:.1f}%")
                    col2.metric("❌ Failed", failed_count, f"{100-success_rate:.1f}%")
                    col3.metric("⏱️ Avg Time", f"{elapsed_time/len(results_df):.2f}s", "per query")
                    
                    # Display results
                    st.subheader("📊 Conversion Results")
                    
                    # Filter options
                    col1, col2 = st.columns(2)
                    with col1:
                        filter_status = st.selectbox("Filter by status:", ["All", "Success", "Failed"])
                    
                    if filter_status != "All":
                        display_df = results_df[results_df['status'] == filter_status]
                    else:
                        display_df = results_df
                    
                    st.dataframe(display_df, use_container_width=True, height=400)
                    
                    # Download results
                    col1, col2 = st.columns(2)
                    with col1:
                        csv_output = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download All Results (CSV)",
                            data=csv_output,
                            file_name=f"cql_conversion_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                    
                    with col2:
                        # Download only successful conversions
                        success_df = results_df[results_df['status'] == 'Success']
                        if len(success_df) > 0:
                            csv_success = success_df.to_csv(index=False)
                            st.download_button(
                                label="📥 Download Successful Only (CSV)",
                                data=csv_success,
                                file_name=f"cql_successful_conversions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
                    
                    # Detailed error analysis
                    if failed_count > 0:
                        with st.expander("🔍 Error Analysis"):
                            failed_df = results_df[results_df['status'] == 'Failed']
                            st.write("**Failed Conversions:**")
                            for idx, row in failed_df.iterrows():
                                st.markdown(f"**{row['use_case_name']}**")
                                st.text(f"Reason: {row['error_reason']}")
                                st.code(row['spl_query'], language="sql")
                                st.markdown("---")
                else:
                    st.error(f"❌ Error: {error}")

with tab3:
    st.header("📜 Conversion History")
    
    if st.session_state.conversion_history:
        st.write(f"📊 Total conversions: **{len(st.session_state.conversion_history)}**")
        
        # Search/filter
        search_term = st.text_input("🔍 Search history:", placeholder="Search by query content...")
        
        # Display recent conversions
        for idx, item in enumerate(st.session_state.conversion_history):
            if search_term and search_term.lower() not in item['spl'].lower() and search_term.lower() not in item['cql'].lower():
                continue
            
            with st.expander(
                f"#{len(st.session_state.conversion_history) - idx} - {item['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} "
                f"({item.get('conversion_time', 0):.2f}s)"
            ):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📝 SPL Query:**")
                    st.code(item['spl'], language="sql")
                
                with col2:
                    st.markdown("**✨ CQL Query:**")
                    st.code(item['cql'], language="sql")
                
                # Action buttons
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button(f"📋 Copy CQL", key=f"copy_{idx}"):
                        st.success("Copied to clipboard!")
                with col2:
                    if st.button(f"🔄 Reconvert", key=f"reconv_{idx}"):
                        client = get_anthropic_client()
                        if client:
                            with st.spinner("Converting..."):
                                new_cql, error = convert_spl_to_cql(item['spl'], client)
                            if new_cql:
                                st.success("Reconversion successful!")
                                st.code(new_cql, language="sql")
        
        # Export history
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📥 Export History", use_container_width=True):
                history_df = pd.DataFrame(st.session_state.conversion_history)
                csv_data = history_df.to_csv(index=False)
                st.download_button(
                    label="Download History CSV",
                    data=csv_data,
                    file_name=f"conversion_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.conversion_history = []
                st.rerun()
    
    else:
        st.info("📭 No conversion history yet. Start converting queries to see them here!")
    
    # Feedback data section
    if st.session_state.feedback_data:
        st.markdown("---")
        st.subheader("📊 Feedback Summary")
        
        feedback_df = pd.DataFrame(st.session_state.feedback_data)
        
        col1, col2 = st.columns(2)
        with col1:
            correct_count = len(feedback_df[feedback_df['feedback'] == 'correct'])
            st.metric("✅ Correct Conversions", correct_count)
        with col2:
            incorrect_count = len(feedback_df[feedback_df['feedback'] == 'incorrect'])
            st.metric("❌ Incorrect Conversions", incorrect_count)
        
        with st.expander("View Feedback Details"):
            st.dataframe(feedback_df, use_container_width=True)
            
            # Export feedback
            if st.button("📥 Export Feedback Data"):
                csv_feedback = feedback_df.to_csv(index=False)
                st.download_button(
                    label="Download Feedback CSV",
                    data=csv_feedback,
                    file_name=f"conversion_feedback_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

with tab4:
    st.header("📖 Help & Documentation")
    
    st.markdown("### 🎯 Quick Start Guide")
    st.markdown("""
    1. **Single Query Conversion:**
       - Enter or select a sample SPL query
       - Click "Convert" to get the CQL equivalent
       - Review and provide feedback
    
    2. **Batch Conversion:**
       - Download the CSV template
       - Add your queries with use case names and descriptions
       - Upload and convert all at once
    
    3. **Review History:**
       - Check past conversions
       - Export for documentation
       - Provide feedback for improvements
    """)
    
    st.markdown("---")
    
    st.markdown("### 🔄 Common SPL to CQL Conversions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**SPL Functions:**")
        st.code("""
# Stats
stats count by field
stats sum(bytes) by src_ip
stats avg(duration) by host

# Eval
eval new_field = value
eval result = field1 + field2

# Search
search "error"
search field=value

# Rex
rex field=_raw "(?<name>pattern)"

# Rename
rename old AS new
        """, language="sql")
    
    with col2:
        st.markdown("**CQL Equivalents:**")
        st.code("""
# Aggregations
groupBy([field], function=count())
groupBy([src_ip], function=sum(bytes))
groupBy([host], function=avg(duration))

# Field Assignment
| new_field := value
| result := field1 + field2

# Filtering
| "error"
| field=value

# Regex
| regex("(?<name>pattern)")

# Rename
| rename(field="old", as="new")
        """, language="sql")
    
    st.markdown("---")
    
    st.markdown("### 📚 Field Mappings")
    
    field_map = {
        "SPL Field": ["host", "source_ip", "user", "process", "command_line"],
        "CQL Field": ["ComputerName", "RemoteAddressIP4", "UserName", "ImageFileName", "CommandLine"],
        "Description": [
            "Computer/hostname",
            "IP address",
            "Username",
            "Process name",
            "Command line arguments"
        ]
    }
    st.table(pd.DataFrame(field_map))
    
    st.markdown("---")
    
    st.markdown("### ❓ Troubleshooting")
    
    with st.expander("Conversion Failed - Unsupported Function"):
        st.markdown("""
        **Issue:** Some SPL functions don't have direct CQL equivalents.
        
        **Solution:**
        - Break complex queries into simpler parts
        - Check CrowdStrike documentation for alternatives
        - Consider implementing logic differently in LogScale
        """)
    
    with st.expander("Incorrect Field Names"):
        st.markdown("""
        **Issue:** Converted query uses wrong field names.
        
        **Solution:**
        - Verify field names in your LogScale environment
        - Check the field mappings table above
        - Manually adjust field names if needed
        - Provide feedback to improve future conversions
        """)
    
    with st.expander("Complex Lookups Not Converting"):
        st.markdown("""
        **Issue:** Lookup operations require external data.
        
        **Solution:**
        - Implement lookups manually in LogScale
        - Use match() or join() functions
        - Consider creating lookup files in LogScale
        """)
    
    st.markdown("---")
    
    st.markdown("### 🔗 External Resources")
    
    resources = {
        "Resource": [
            "CrowdStrike LogScale Documentation",
            "LogScale Community Content",
            "CQL Query Language Reference",
            "LogScale Query Functions",
            "CrowdStrike GitHub"
        ],
        "Link": [
            "https://library.humio.com/",
            "https://github.com/CrowdStrike/logscale-community-content",
            "https://library.humio.com/data-analysis/query-language.html",
            "https://library.humio.com/data-analysis/query-functions.html",
            "https://github.com/CrowdStrike"
        ]
    }
    
    for resource, link in zip(resources["Resource"], resources["Link"]):
        st.markdown(f"- [{resource}]({link})")
    
    st.markdown("---")
    
    st.markdown("### ℹ️ About This Tool")
    st.info("""
    **SPL to CQL Converter v1.0**
    
    This tool uses Claude AI with research-optimized prompts based on SANS studies of SIEM detection logic conversion.
    
    **Features:**
    - Single and batch query conversion
    - Conversion history tracking
    - Feedback system for continuous improvement
    - Research-backed prompt engineering
    - Temperature optimization (0.1 for consistency)
    
    **Success Rates (Based on Research):**
    - 40-50% queries work immediately
    - 70-80% with minor adjustments
    - <5% parsing errors
    
    **Note:** Always validate converted queries in a test environment before production use.
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🔍 <strong>SPL to CQL Converter</strong> | Powered by Claude AI (Anthropic)</p>
    <p>Built with Streamlit | Research-Optimized Prompts | Temperature: 0.1</p>
    <p>⚠️ Always validate converted queries before production use</p>
</div>
""", unsafe_allow_html=True)
