<p align="center">
  <a href="README.md">简体中文</a> · <a href="README.en.md">English</a>
</p>

# AiVerse Script Plugin Repository

This repository is the **script plugin repository** for [AiVerse](https://github.com/yhdmgf/AiVerse): it hosts installable script plugins (zip packages + `index.json` manifest). Once installed, a plugin registers as a **tool** for AiVerse, so the AI (Agent) can invoke it during conversation.

## What Do Script Plugins Do?

A script plugin defines one or more **tools** (`name` + `description` + `parameters` + `handler`) in JavaScript. When installed into AiVerse, it is automatically registered to the AI. The AI can see these tools (their descriptions are injected into the context); when you ask it to perform the corresponding operation (e.g. "read the clipboard", "send a notification"), it invokes the plugin's `handler` and returns the result to you.

Each plugin declares the permissions it needs (`clipboard` / `notify`, etc.); AiVerse prompts for authorization on install.

## Installation

In AiVerse's **Script Plugins** page → tap **From repository** (top-right) → enter this repo address `https://github.com/yhdmgf/aiverseRules` → list and install.

## Plugins

### Clipboard Tool (v1.0.0)

- Package `com.aiverse.clipboard`, permission `clipboard`.
- Description: read the system clipboard text content.
- Tools:

| Tool | Parameters | Description |
|---|---|---|
| `get` | none | Read clipboard text, return content |

- **AI usage example**: tell the AI "**read the clipboard**" → the AI calls `clipboardTool.get()`, returning the clipboard text.

### Notification Tool (v1.0.1)

- Package `com.aiverse.notify`, permission `notify`.
- Description: send a system status-bar notification (tap opens the app).
- Tools:

| Tool | Parameters | Description |
|---|---|---|
| `send` | `title` (required, notification title), `body` (required, notification body) | Send a notification |

- **AI usage example**: tell the AI "**send a notification, title 'Task done', body '3 files written'**" → the AI calls `notifyTool.send({ title: "Task done", body: "3 files written" })`.

## How the AI Invokes Tools (Usage)

After installation, the AI treats plugin tools as ordinary tools:

1. **Install**: AiVerse → Script Plugins → From repository → enter this repo URL → install (authorize as needed).
2. **Trigger in conversation**: just ask the AI in natural language. Plugin tool descriptions appear in the AI's tool list, so it knows when and how to pass arguments.
3. **Permissions**: the plugin's declared permissions (`clipboard` / `notify`) are requested from AiVerse at install time; the tool is unavailable unless authorized.

## Structure

- `index.json`: plugin manifest (name / version / permission / package). AiVerse lists installable plugins from it.
- `*.zip`: each plugin's zip package (contains `plugin.json` descriptor + `main.js` tool definitions); the filename matches an `index.json` entry.

## Updating a Plugin

After modifying a plugin, update the corresponding zip and `index.json` (version, permission, `lastUpdate`), then commit and push.
