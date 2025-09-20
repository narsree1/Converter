# SPL to CQL Converter - Deployment Guide

## 🚀 Quick Start

This Streamlit application converts Splunk SPL queries to CrowdStrike Falcon LogScale CQL queries using Claude AI.

## 📋 Prerequisites

1. **Anthropic API Key** - Get one from [Anthropic Console](https://console.anthropic.com/)
2. **GitHub Account** - For repository hosting
3. **Streamlit Cloud Account** - Free tier available at [share.streamlit.io](https://share.streamlit.io)

## 🛠️ Setup Instructions

### Step 1: Create GitHub Repository

1. Create a new repository on GitHub
2. Add these files:
   - `app.py` - Main Streamlit application
   - `requirements.txt` - Python dependencies
   - `README.md` - This file

### Step 2: Configure Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Click "New app"
3. Select your GitHub repository
4. Set main file path: `app.py`
5. Click "Advanced settings"
6. Add secrets:
   ```toml
   ANTHROPIC_API_KEY = "your-api-key-here"
   ```
7. Click "Deploy"

## 📁 File Structure

```
spl-to-cql-converter/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
└── README.md             # Documentation
```

## 🔧 Configuration

### Environment Variables

Add your Anthropic API key as a secret in Streamlit Cloud:

1. Go to your app settings
2. Navigate to "Secrets"
3. Add:
   ```toml
   ANTHROPIC_API_KEY = "sk-ant-..."
   ```

### Local Development

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd spl-to-cql-converter
   ```

2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set environment variable:
   ```bash
   export ANTHROPIC_API_KEY="your-api-key"  # On Windows: set ANTHROPIC_API_KEY=your-api-key
   ```

5. Run the app:
   ```bash
   streamlit run app.py
   ```

## 📊 Features

### 1. Single Query Conversion
- Convert individual SPL queries to CQL
- Real-time conversion with validation
- Syntax highlighting for both SPL and CQL

### 2. Batch CSV Upload
- Process multiple queries at once
- CSV format with columns:
  - `use_case_name`: Detection rule name
  - `description`: What the rule detects
  - `spl_query`: SPL query to convert
- Download results as CSV

### 3. Conversion History
- Track all conversions in session
- Review past conversions
- Export history as CSV

### 4. Feedback System
- Mark conversions as correct/incorrect
- Build training dataset for improvements
- Export feedback data

## 🔍 Usage Examples

### Single Query
```sql
index=main sourcetype=WinEventLog:Security EventCode=4625 
| stats count by src_ip, user 
| where count > 5
```

Converts to:
```sql
#event_simpleName=UserLogonFailed
| groupBy([RemoteAddressIP4, UserName], function=count())
| count > 5
```

### CSV Batch Upload

Download the sample CSV template and populate with your queries:

| use_case_name | description | spl_query |
|--------------|-------------|-----------|
| Failed Logins | Detect brute force | `index=main EventCode=4625 | stats count by user` |
| PowerShell Exec | Suspicious PS commands | `index=main PowerShell | search EncodedCommand=*` |

## 🎯 Key Mappings

| SPL | CQL Equivalent |
|-----|----------------|
| `stats count by field` | `groupBy([field], function=count())` |
| `eval new_field = value` | `| new_field := value` |
| `rename field1 as field2` | `| rename(field="field1", as="field2")` |
| `rex field=_raw "(?<extract>...)"` | `| regex("(?<extract>...)")` |
| `search term` | `term` or `| term` |

## 📈 Token Optimization

The application is optimized for minimal token usage:
- Concise prompts with clear instructions
- Temperature set to 0.1 for consistency
- Max tokens limited to 2048
- Efficient batch processing

## ⚠️ Important Notes

1. **Always validate** converted queries before production use
2. **Complex queries** may require manual review
3. **Field mappings** should be verified against your specific LogScale setup
4. **API costs** apply based on Anthropic pricing

## 🐛 Troubleshooting

### Common Issues

1. **"ANTHROPIC_API_KEY not found"**
   - Ensure API key is set in Streamlit Cloud secrets
   - Check for typos in the secret name

2. **"Conversion Failed"**
   - Verify SPL query syntax
   - Simplify complex queries
   - Check for unsupported SPL functions

3. **CSV Upload Errors**
   - Ensure CSV has required columns
   - Check for encoding issues (use UTF-8)
   - Verify CSV format matches template

## 🔄 Updates and Improvements

To update the application:
1. Modify files in your GitHub repository
2. Streamlit Cloud auto-deploys on push

## 📝 Feedback and Training

The application includes a feedback mechanism to improve conversions:
- Mark conversions as correct/incorrect
- Export feedback data for analysis
- Use feedback to refine prompts

## 🔗 Resources

- [CrowdStrike LogScale Documentation](https://library.humio.com/)
- [LogScale Community Content](https://github.com/CrowdStrike/logscale-community-content)
- [Anthropic Claude Documentation](https://docs.anthropic.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)

## 📜 License

This project is for educational and research purposes. Always validate conversions before production use.

## 🤝 Contributing

To contribute improvements:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 💡 Tips

- Start with simple queries to understand conversion patterns
- Use the sample queries to test functionality
- Review LogScale documentation for field mappings
- Keep the Claude model updated to latest version
- Monitor API usage to manage costs

## 🎓 Learning Resources

### Understanding SPL to CQL Conversion

1. **Field Mappings**: Different SIEM platforms use different field names
2. **Function Translation**: SPL and CQL have different function syntaxes
3. **Security Context**: Maintain detection logic integrity
4. **Performance**: CQL queries are optimized differently than SPL

### Best Practices

1. Test converted queries in a development environment
2. Validate field existence in your LogScale setup
3. Adjust time ranges appropriately
4. Consider performance implications
5. Document any manual adjustments needed

## 📞 Support

For issues or questions:
- Check the troubleshooting section
- Review CrowdStrike documentation
- Consult the conversion history for patterns
- Use the feedback system to report issues

---

**Built with ❤️ using Claude AI and Streamlit**
