<div align="center">

# Scam Detector MCP

**MCP server for scam detector mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-scam-detector-mcp)](https://pypi.org/project/meok-scam-detector-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Scam Detector MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `quick_check` | Paste any message (email, text, DM) -> instant scam probability score. No API ke |
| `analyze_url` | Check a URL for phishing indicators and suspicious patterns. |
| `detect_social_engineering` | Detect manipulation tactics (Cialdini's principles) in conversations. |
| `verify_sender` | Check sender patterns against known scam vectors. |
| `report_scam` | Log and analyze a scam report. Contributes to collective threat intelligence. |

## Installation

```bash
pip install meok-scam-detector-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "scam-detector-mcp": {
      "command": "python",
      "args": ["-m", "meok_scam_detector_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
