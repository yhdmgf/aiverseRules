# AiVerse Script Plugin Repository

This repository is the **script plugin repository** for [AiVerse](https://github.com/yhdmgf/AiVerse): it hosts installable script plugins (zip packages + `index.json` manifest).

## Installation

In AiVerse's **Script Plugins** page → tap **From repository** (top-right) → enter this repo address (`https://github.com/yhdmgf/aiverseRules`) → list and install plugins.

## Plugins

| Plugin | Version | Permission | Description |
|---|---|---|---|
| Clipboard Tool | 1.0.0 | `clipboard` | Read / write clipboard |
| Notification Tool | 1.0.1 | `notify` | Send system notification |

## Structure

- `index.json`: plugin manifest (name / version / permission / package). AiVerse lists installable plugins from it.
- `*.zip`: each plugin's zip package; the filename matches an entry in `index.json`.

## Updating a Plugin

After modifying a plugin, update the corresponding zip and `index.json` (version, permission, `lastUpdate`), then commit and push.
