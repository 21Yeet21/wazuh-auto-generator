# Wazuh Decoder Auto-Generator: Architecture & Engineering Log

> [!NOTE]
> **Project Evolution**
> **Phase 1** attempted to use a local LLM (Llama-3 via Ollama) to generate Wazuh decoders. This failed due to LLM regex hallucinations and JSON escaping nightmares.
> 
> **Phase 2** evolved into a **Deterministic Python Heuristic Engine**. We abandoned AI in favor of pure Python logic, utilizing an "Anchor & Bridge" architecture to bypass Wazuh's strict PCRE2 syntax quirks and achieve 100% reliable extraction.

---

## Core Infrastructure: The Anchor & Bridge Engine

The hardest architectural shift in Phase 2 was moving from *LLM-generated static text matching* to **dynamic non-greedy bridging**.

> [!WARNING]
> **Why `re.escape()` Failed in Wazuh**
> In Phase 1, the engine used Python's `re.escape()` to wrap static text between dynamic fields. This aggressively escaped dashes (`\-`) and brackets (`\[`). Wazuh's internal `OSRegex` and `PCRE2` engines notoriously throw `Syntax error on regex` when encountering these escaped characters, causing the Wazuh Manager to crash on restart.
> 
> **The Fix:** We abandoned `re.escape()` entirely. We implemented the "Anchor & Bridge" method. 

### The New Pipeline
1.  **Anchor Identification:** The engine scans the log for the first solid alphanumeric word (e.g., `ERR`, `DEVICE`). This becomes the `<prematch>`.
2.  **Dynamic Field Identification:** Python heuristics identify IPs, Key-Value pairs, and Quoted Strings using strict boundaries (`([^,\s\)\];]+)`).
3.  **The PCRE2 Bridge (`.*?`):** Instead of matching static text, the engine bridges the gap between dynamic fields using PCRE2 non-greedy matching (`.*?`). This tells the regex engine to skip characters until the next field is found.

---

## Deep Dive: The PCRE2 Quirks

To make the tool 100% bulletproof, we had to engineer solutions for three hidden Wazuh architecture quirks.

### 1. The `OSRegex` vs `PCRE2` Bug
*   **The Problem:** The engine generated `\d{1,3}` for IP addresses. Wazuh's default engine (`OSRegex`) silently failed to match this, resulting in zero fields extracted.
*   **The Fix:** We explicitly tagged the regex with `<regex type="pcre2">`. This unlocked full PCRE2 support, allowing the use of `\d`, `\S`, and non-greedy `.*?` bridges.

### 2. The Timestamp Capture Group Bug
*   **The Problem:** The engine wrapped timestamps in a capture group `()` and mapped them to `timestamp` in the `<order>` tag. Wazuh silently rejected this. Wazuh parses timestamps internally and does not allow `timestamp` in the `<order>` list. If the capture groups are misaligned, all fields extract as blank.
*   **The Fix:** The engine still matches the timestamp pattern (e.g., `\d{4}-\d{2}-\d{2}T\S*`), but it **does not** wrap it in a capture group and **does not** add it to the `<order>` list.

### 3. The Punctuation-Swallowing Bug
*   **The Problem:** Key-Value pairs were extracted using `(\S+)`. In logs like `code=403, attempt=3)`, the `\S+` swallowed the comma and parenthesis, extracting `403,` instead of `403`.
*   **The Fix:** We implemented strict KV boundaries: `([^,\s\)\];]+)`. This tells the regex to match anything *except* commas, spaces, closing parentheses, or semicolons.

---

## Deep Dive: Bulk Processing Signatures

To enable bulk processing of 1,000 logs at once, the engine needed a way to group logs by structural pattern without relying on the exact values.

### The Signature Pipeline
1.  **Sanitization:** The engine takes a raw log and replaces all dynamic values with placeholders:
    *   IPs become `<IP>`
    *   Quoted strings become `<STR>`
    *   Timestamps become `<TS>`
    *   Key-Value pairs become `<KV>`
2.  **Grouping:** The engine hashes these signatures and groups the logs.
3.  **Frequency Analysis:** It sorts the groups by volume and returns the top 3 patterns, providing a one-click link to generate a decoder for each pattern's sample log.

---

## War Stories: Phase 2 Challenges

### 1. The Syslog Built-in Intercept
*   **The Problem:** The engine generated a perfect decoder for a standard Syslog log (`Oct 24 10:15:30 server sshd[1234]: ...`). But `wazuh-logtest` ignored it and fired a generic syslog rule.
*   **The Cause:** Wazuh evaluates built-in decoders first. Its native `syslog` decoder intercepted the log, parsed the timestamp and hostname, and stopped processing before our custom decoder could run.
*   **The Fix:** This is actually intended Wazuh behavior. The tool is designed for *proprietary, unstructured* logs that Wazuh doesn't have built-in decoders for. We documented this limitation in the UI.

### 2. The Child Decoder Silent Failure
*   **The Problem:** The engine generated a Parent decoder (`<prematch>`) and a Child decoder (`<regex>`). The parent matched, but the child extracted nothing.
*   **The Cause:** When a parent decoder matches a `prematch`, Wazuh "consumes" that text. The child decoder then tries to apply its regex to the *remaining* text. If the child regex expected the text from the beginning of the line, it failed silently.
*   **The Fix:** We configured the engine to skip any dynamic fields that overlap with the anchor word, ensuring the child regex only looks for fields that appear *after* the anchor.
