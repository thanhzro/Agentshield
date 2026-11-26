# AgentShield

> Zero-dependency, read-only security & prompt-injection auditor for AI coding agents and MCP configurations.

Developers install `SKILL.md` files, `.cursorrules`, `CLAUDE.md`, and `mcp.json` servers every day. **AgentShield** audits them locally in milliseconds—with **no third-party dependencies** and **no network calls**.

## What It Catches

- **Hardcoded Credentials:** OpenAI, Anthropic, GitHub, Google, AWS, and Slack tokens inside agent configs.
- **Hidden Prompt Injection:** Zero-width characters, bidirectional Unicode overrides (`U+202E`), and instruction-override phrases.
- **Dangerous Execution Patterns:** `curl | bash`, `base64 -d | sh`, and destructive `rm -rf` targets.
- **Risky MCP Server Configs:** Raw shell wrappers (`bash`, `powershell`), unpinned `npx -y`, and plaintext secrets inside `mcpServers.*.env`.

## Quick Start

Download `agentshield.py` and run it with Python 3.10+ (no `pip install` needed):

```bash
python3 agentshield.py /path/to/your/repo
```

### CI / JSON Output

```bash
python3 agentshield.py . --json --fail-on medium
```

### Example Output

```text
[HIGH] SKILL.md:1 (pipe-to-shell) - Remote script piped directly to shell.
[HIGH] mcp.json:1 (mcp-plaintext-env-secret) - MCP server 'demo' may contain a plaintext secret in env var 'OPENAI_API_KEY'.
```

## License

MIT
