"""
Configuration file for SPL to CQL Converter
Contains the conversion prompt and settings
"""

# Claude API Settings
CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 2048
TEMPERATURE = 0.1  # Research-proven optimal: 0.1-0.2 for consistency

# Conversion Prompt - Optimized based on SANS research
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

# Sample queries for testing
SAMPLE_QUERIES = {
    "Failed Login Attempts": """index=main sourcetype=WinEventLog:Security EventCode=4625 
| stats count by src_ip, user 
| where count > 5""",
    
    "PowerShell Encoded Command": """index=main sourcetype=WinEventLog:PowerShell 
| search EncodedCommand=* 
| table _time, host, CommandLine""",
    
    "Suspicious Process Execution": """index=main sourcetype=WinEventLog:Security EventCode=4688 
| eval cmdline=lower(CommandLine) 
| search cmdline="*powershell*" OR cmdline="*cmd.exe*" 
| stats count by user, parent_process""",
    
    "Network Connection to Suspicious IP": """index=main sourcetype=firewall 
| search dest_ip IN (192.168.1.100, 10.0.0.50) 
| stats sum(bytes) as total_bytes by src_ip, dest_port 
| where total_bytes > 1000000""",
    
    "Multiple Failed SSH Attempts": """index=main sourcetype=linux_secure 
| rex field=_raw "Failed password for (?<user>\\w+) from (?<src_ip>[\\d.]+)" 
| stats count by src_ip, user 
| where count > 10"""
}

# Field mapping reference
FIELD_MAPPINGS = {
    # Common SPL to CQL field mappings
    "host": "ComputerName",
    "source_ip": "RemoteAddressIP4",
    "src_ip": "RemoteAddressIP4",
    "dest_ip": "RemoteAddressIP4",
    "user": "UserName",
    "username": "UserName",
    "process": "ImageFileName",
    "process_name": "ImageFileName",
    "parent_process": "ParentBaseFileName",
    "command_line": "CommandLine",
    "cmdline": "CommandLine",
    "file_path": "TargetFileName",
    "file_name": "TargetFileName",
    "registry_path": "RegObjectName",
    "registry_value": "RegValueName",
    "event_id": "EventID",
    "event_code": "EventID",
    "computer": "ComputerName",
    "hostname": "ComputerName",
    "domain": "UserDomain"
}

# Function mapping reference
FUNCTION_MAPPINGS = {
    "stats count": "groupBy(..., function=count())",
    "stats sum": "groupBy(..., function=sum())",
    "stats avg": "groupBy(..., function=avg())",
    "stats max": "groupBy(..., function=max())",
    "stats min": "groupBy(..., function=min())",
    "stats dc": "groupBy(..., function=count(distinct=true))",
    "eval": "field := value",
    "rename": "rename(field=\"old\", as=\"new\")",
    "search": "filter with |",
    "where": "conditional filter with |",
    "rex": "regex(\"pattern\")",
    "dedup": "groupBy() with limit",
    "sort": "sort()",
    "head": "head() or tail()",
    "table": "select fields"
}

# Error messages
ERROR_MESSAGES = {
    "unsupported_function": "ERROR: Unsupported SPL function - no direct CQL equivalent",
    "complex_lookup": "ERROR: Complex lookup requiring external data source - manual implementation needed",
    "macro_detected": "ERROR: SPL macro detected - expand macro before conversion",
    "invalid_syntax": "ERROR: Invalid SPL syntax - please verify query",
    "time_complexity": "ERROR: Complex time window operation - manual adjustment required"
}

# Conversion tips
CONVERSION_TIPS = [
    "Use #event_simpleName for event filtering in CQL",
    "CQL uses := for field assignment, not = like SPL",
    "groupBy() in CQL requires explicit function specification",
    "Regex in CQL uses /pattern/ syntax, not quotes",
    "Time selectors in CQL: @timestamp > -24h",
    "Case statements in CQL use | case { condition | action ; ... }",
    "Join operations in CQL use join() with specific syntax",
    "Wildcards in CQL: * for any characters, ? for single character"
]
