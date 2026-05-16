

# Autopsy MCP

<p align="center">
  <img src="logo.png" alt="Autopsy MCP Logo" width="180" />
</p>

autopsyMCP is a Model Context Protocol (MCP) server that enables LLMs to autonomously perform digital forensics and analysis using Autopsy. It exposes a wide range of Autopsy’s core forensic tools and features to any MCP client, allowing automated investigation and evidence extraction workflows.

**Works with any MCP client.**

The instructions below use Claude Desktop as an example, but you can connect autopsyMCP to any compatible MCP client.

No API key. No second AI service. No Autopsy plugins.

Claude Desktop calls the tools, gets the forensic data back, and reasons over it — Claude *is* the analysis layer.

---

## How it works

```
You talk to Claude Desktop
        |
        v
Claude calls MCP tools (e.g. "get web history artifacts")
        |
        v
autopsy_mcp.py reads the Autopsy .db file  (read-only SQLite)
        |
        v
Returns raw forensic data back to Claude Desktop
        |
        v
Claude analyzes, correlates, and explains the evidence to you
```

The `.db` file is the SQLite database Autopsy creates automatically for every
case. Find its path in Autopsy -> Case -> Case Properties.

---


## Installation (one-time)

Requires: Python 3.10+, and an MCP client (e.g., Claude Desktop)

```bash
pip install fastmcp pydantic
```

---


## Setup with Claude Desktop (example)

Open your Claude Desktop config file:

| OS      | Path |
|---------|------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS   | `~/Library/Application Support/Claude/claude_desktop_config.json` |

Add the `autopsy` entry (replace the path with your actual path):

```json
{
  "mcpServers": {
    "autopsy": {
      "command": "python",
      "args": ["C:/path/to/autopsy_mcp/autopsy_mcp.py"]
    }
  }
}
```

**Restart Claude Desktop.** The tools will appear in the tools panel.

---

## Setup with Other MCP Clients

autopsyMCP can be used with any MCP-compatible client. Refer to your client’s documentation for how to add or configure a custom MCP server, using the path to `autopsy_mcp.py` as the server entry point.

---

## Usage

Just talk to Claude and give it your `.db` path:

```
Analyse my Autopsy case at C:\Cases\Investigation1\Investigation1.db

What artifact types are in C:\Cases\Investigation1\Investigation1.db?

Show me the web history and look for anything suspicious

Look at the web history and emails together for signs of data exfiltration

Triage this case and tell me the most important findings
```

Claude calls the tools, pulls the data, and gives you a full forensic analysis.

---

## Available Tools

| Tool | What it fetches |
|------|----------------|
| `autopsy_case_info` | Case metadata, data sources, disk images, ingest module history |
| `autopsy_list_artifact_types` | All artifact types present with counts — run this first |
| `autopsy_get_artifacts` | Artifacts of a specific type with all attribute values |
| `autopsy_get_multiple_artifact_types` | Sample from 2-6 types at once (great for correlation) |
| `autopsy_search_files` | Files by name/path pattern using SQL % wildcards |
| `autopsy_get_timeline` | Timeline events with optional Unix timestamp range |
| `autopsy_tagged_items` | Examiner-tagged files and artifacts with comments |
| `autopsy_hash_hits` | All hash set hits (malware / notable file matches) |
| `autopsy_file_metadata` | Full metadata for one file by obj_id |

---

## Code Layout

The server is split into small modules so changes can be reviewed and committed
progressively:

| Path | Purpose |
|------|---------|
| `autopsy_mcp.py` | Thin launcher kept for Claude Desktop compatibility |
| `autopsy_mcp_server/server.py` | FastMCP server construction |
| `autopsy_mcp_server/app.py` | Imports tool modules so they register with FastMCP |
| `autopsy_mcp_server/constants.py` | Artifact keys, default roots, timestamp constants |
| `autopsy_mcp_server/discovery.py` | Case discovery and `case_name` resolution |
| `autopsy_mcp_server/database.py` | Read-only SQLite connection and query helpers |
| `autopsy_mcp_server/formatting.py` | Timestamp and pagination formatting |
| `autopsy_mcp_server/artifact_helpers.py` | Shared artifact lookup/fetch helpers |
| `autopsy_mcp_server/schemas.py` | Pydantic input models |
| `autopsy_mcp_server/tools/` | Tool implementations grouped by feature |

See `COMMIT_SEGMENTS.md` for a 17-step commit progression.

---

## Supported Artifact Type Keys

```
WEB_HISTORY    WEB_DOWNLOAD    WEB_COOKIE      WEB_SEARCH    WEB_BOOKMARK
EMAIL          INSTALLED_PROG  DEVICE_ATTACHED RECENT_OBJECT CONTACT
MESSAGE        CALL_LOG        CALENDAR        KEYWORD_HIT   HASH_HIT
ENCRYPTION     INTERESTING_FILE OS_INFO        WIFI_NETWORK  USER_ACCOUNT
SHELL_BAG      GPS_TRACK
```

Use `autopsy_list_artifact_types` first to see which are actually populated.

---

## Notes

- The server opens `.db` files **read-only** and cannot modify your case.
- `timeline_events` is only populated after you open Autopsy's Timeline view
  (Tools -> Timeline) at least once.
- Tested against Autopsy 4.19-4.21 SQLite schema.
