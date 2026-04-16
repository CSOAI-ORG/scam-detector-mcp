# Scam Detector MCP Server

By [MEOK AI Labs](https://meok.ai) | The only MCP server for scam and fraud detection.

## Quick Start

```bash
pip install scam-detector-mcp
scam-detector-mcp
```

Or run directly:

```bash
pip install mcp
python server.py
```

## Claude Desktop Config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scam-detector": {
      "command": "scam-detector-mcp"
    }
  }
}
```

## Tools

| Tool | Description | API Key Required |
|------|-------------|-----------------|
| `quick_check` | Paste any message, get instant scam probability | No |
| `analyze_url` | Check URL for phishing indicators | No (free tier) |
| `detect_social_engineering` | Detect manipulation tactics in conversations | No (free tier) |
| `verify_sender` | Check sender patterns against known scam vectors | No (free tier) |
| `report_scam` | Log and analyze a scam report | No (free tier) |

## Free Tier

10 calls/day per tool, no API key required. Upgrade to Pro ($29/mo) for unlimited access at [meok.ai](https://meok.ai/mcp/scam-detector/pro).

## Examples

### Quick Check (zero config)
```
quick_check("URGENT: Your account has been suspended. Click here to verify your identity immediately or lose access.")
```

### Analyze URL
```
analyze_url("http://paypa1-security.xyz/login/verify")
```

### Detect Social Engineering
```
detect_social_engineering("Hi, I'm from your bank's fraud department. We've detected suspicious activity. I need your account number to verify your identity right away.")
```

## License

MIT - Built by [MEOK AI Labs](https://meok.ai)
