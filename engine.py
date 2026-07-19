import re
from collections import defaultdict
from urllib.parse import quote

def generate_wazuh_config(raw_log: str) -> str:
    """Pure Python heuristic engine using the Anchor & Bridge architecture (Wazuh Compliant)."""
    raw_log = raw_log.strip()
    print(f"[*] Analyzing log with Anchor & Bridge: {raw_log}")
    
    # Step 1: Find the Anchor
    anchor_match = re.search(r'\b[A-Za-z0-9_-]{3,}\b', raw_log)
    if anchor_match:
        anchor = anchor_match.group(0)
        anchor_start = anchor_match.start()
        anchor_end = anchor_match.end()
    else:
        anchor = r"^\S+"
        anchor_start = -1
        anchor_end = -1
        
    # Step 2: Identify Dynamic Fields
    patterns = [
        (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'ipv4'),
        (re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE), 'ipv6'),
        (re.compile(r'[\w\.\-]+@[\w\-]+\.[\w\.\-]+'), 'email'),
        (re.compile(r'(\w+)=([^,\s\)\];]+)'), 'kv'), # Key-Value pairs with strict boundaries
        (re.compile(r"'([^']+)'"), 'quote_single'),
        (re.compile(r'"([^"]+)"'), 'quote_double'),
    ]
    
    matches = []
    for pat, ptype in patterns:
        for m in pat.finditer(raw_log):
            matches.append((m.start(), m.end(), m, ptype))
            
    matches.sort(key=lambda x: x[0])
    
    # Remove overlapping matches AND skip matches that overlap with the anchor
    clean_matches = []
    last_end = 0
    for start, end, m, ptype in matches:
        if start < anchor_end and end > anchor_start:
            continue
            
        if start >= last_end:
            clean_matches.append((start, end, m, ptype))
            last_end = end
            
    # Step 3: Build the Regex (Anchor & Bridge)
    wazuh_regex = ".*?"
    order_list = []
    ip_count = 0
    data_count = 0
    
    for start, end, m, ptype in clean_matches:
        if ptype == 'ipv4':
            wazuh_regex += r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            if ip_count == 0: order_list.append("srcip")
            else: order_list.append("dstip")
            ip_count += 1
            
        elif ptype == 'ipv6':
            wazuh_regex += r"([A-F0-9:]+)"
            if ip_count == 0: order_list.append("srcip")
            else: order_list.append("dstip")
            ip_count += 1
            
        elif ptype == 'email':
            wazuh_regex += r"([\w\.\-]+@[\w\-]+\.[\w\.\-]+)"
            order_list.append("email")
            
        elif ptype == 'kv':
            key = m.group(1)
            clean_key = re.sub(r'\W', '_', key).lower()
            
            if clean_key in ['user', 'username', 'account', 'srcuser', 'user_id']:
                field_name = "user"
            elif clean_key in ['srcip', 'source_ip']:
                field_name = "srcip"
            elif clean_key in ['dstip', 'dest_ip']:
                field_name = "dstip"
            else:
                field_name = clean_key
                
            wazuh_regex += f"{key}=([^,\\s\\)\\];]+)"
            order_list.append(field_name)
            
        elif ptype == 'quote_single':
            context = raw_log[max(0, start-15):start].lower()
            wazuh_regex += r"'([^']+)'"
            if 'user' in context or 'account' in context: order_list.append("user")
            else: order_list.append(f"data{data_count}"); data_count += 1
            
        elif ptype == 'quote_double':
            context = raw_log[max(0, start-15):start].lower()
            wazuh_regex += r'"([^"]+)"'
            if 'user' in context or 'account' in context: order_list.append("user")
            else: order_list.append(f"data{data_count}"); data_count += 1
            
        wazuh_regex += ".*?"
        
    if wazuh_regex.endswith(".*?"):
        wazuh_regex = wazuh_regex[:-3]
        
    if not order_list:
        wazuh_regex = f".*?{re.escape(anchor)}.*?"

    # Step 4: Generate Final XML
    desc_fields = []
    for f in order_list:
        if f == 'user': desc_fields.append("$(dstuser)")
        elif f in ['srcip', 'dstip', 'email']: desc_fields.append(f"$({f})")
        
    description = f"Custom event: {' '.join(desc_fields)}" if desc_fields else "Custom log event detected"

    order_str = ", ".join(order_list)
    rule_id = 100001 
    
    xml_output = f"""<!-- DECODER: Save to /var/ossec/etc/decoders/local_decoder.xml -->
<decoder name="custom-app">
    <prematch>{anchor}</prematch>
    <regex type="pcre2">{wazuh_regex}</regex>
    <order>{order_str}</order>
</decoder>

<!-- RULE: Save to /var/ossec/etc/rules/local_rules.xml -->
<group name="custom_logs,">
    <rule id="{rule_id}" level="5">
        <decoded_as>custom-app</decoded_as>
        <description>{description}</description>
        <group>custom_rules,</group>
    </rule>
</group>
"""
    return xml_output

def simulate_wazuh_extraction(raw_log: str, wazuh_regex: str, order_list: list) -> dict:
    """Simulates Wazuh's PCRE2 extraction using Python's re module."""
    clean_regex = wazuh_regex
    
    try:
        match = re.search(clean_regex, raw_log)
        if match:
            extracted_fields = {}
            groups = match.groups()
            for i, field_name in enumerate(order_list):
                if i < len(groups):
                    display_name = "dstuser (user)" if field_name == "user" else field_name
                    extracted_fields[display_name] = groups[i]
            return {"success": True, "fields": extracted_fields}
        else:
            return {"success": False, "error": "Regex did not match the log."}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_log_batch(logs: list) -> list:
    """Analyzes a batch of logs and returns the top 3 most common patterns."""
    pattern_groups = defaultdict(list)
    
    for log in logs:
        log = log.strip()
        if not log:
            continue
        
        # Create a structural signature: Replace dynamic values with placeholders
        signature = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP>', log)
        signature = re.sub(r"'[^']+'", "'<STR>'", signature)
        signature = re.sub(r'"[^"]+"', '"<STR>"', signature)
        signature = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}.*?Z?', '<TS>', signature)
        signature = re.sub(r'\w+=\S+', '<KV>', signature)
        signature = re.sub(r'\b\d+\b', '<NUM>', signature) # Replace standalone numbers
        
        pattern_groups[signature].append(log)
    
    # Sort by frequency and return top 3
    sorted_patterns = sorted(pattern_groups.items(), key=lambda x: len(x[1]), reverse=True)
    
    results = []
    for signature, log_list in sorted_patterns[:3]:
        results.append({
            'signature': signature,
            'count': len(log_list),
            'sample_log': log_list[0],
            'encoded_log': quote(log_list[0]) # URL encode the sample log here
        })
    
    return results