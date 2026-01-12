# ZAFrida UI (PyCharm Plugin)

A Frida UI tool window inside PyCharm / JetBrains IDEs.

## Features
- List devices via `frida-ls-devices`
- Add remote host (host:port) in Settings, without deploying frida-server
- List targets via `frida-ps` (running processes / running apps / installed apps)
- Run/Stop `frida` with a JS script
- JS templates managed by checkboxes:
    - Checked: insert or enable template block
    - Unchecked: comment out template block (never delete)
- Output to IDE ConsoleView + persistent `.log` in project folder (`zafrida-logs/`)

## Requirements
- Your own frida tools in PATH or configured:
    - `frida`
    - `frida-ps`
    - `frida-ls-devices`

## Development
Open in IntelliJ IDEA, then run:
- Gradle task: `runIde`

## Usage
1. Open ZAFrida tool window.
2. Refresh devices, choose device.
3. Load targets and select target.
4. Select script (or create new script).
5. Toggle templates as needed.
6. Click Run.

## Typings (Optional)
Click "Install Typings" to generate minimal `frida-gum.d.ts` into `.zafrida/typings/`.
For full typings, consider installing:
- `npm i -D @types/frida-gum`
