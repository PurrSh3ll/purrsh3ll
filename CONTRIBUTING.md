# Contributing to PurrSh3ll

Thanks for your interest in contributing. PurrSh3ll is a solo project built alongside a full-time job, so contributions — even small ones — are genuinely appreciated.

## How to contribute

### Reporting bugs

Open an issue on GitHub with:
- What you did
- What you expected to happen
- What actually happened
- Your OS and Python version

### Suggesting features

Open an issue with the `enhancement` label. Describe the use case, not just the feature — it helps prioritize what's actually useful.

### Submitting a pull request

1. Fork the repository
2. Create a branch: `git checkout -b fix/your-description`
3. Make your changes
4. Test that the app starts and the affected feature works
5. Open a pull request with a short description of what and why

Keep PRs focused — one fix or feature per PR is easier to review.

## Running the project locally

```bash
git clone https://github.com/PurrSh3ll/purrsh3ll.git
cd purrsh3ll
python3 -m venv .venv
source .venv/bin/activate
pip install PyQt6 PyQt6-WebEngine watchdog chromadb fastembed loguru rich pydantic requests PyYAML Pillow pyte markdown2 Pygments keyring docker pygame pyfiglet numpy jeepney SecretStorage cryptography
# Install QTermWidget wheel from GitHub Releases
pip install https://github.com/PurrSh3ll/purrsh3ll/releases/download/v1.0.0/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl
python main.py
```

## Project structure

```
core/          # Application logic, mixins, controller
gui/           # UI builders, widgets, dialogs
appdata/       # Config, themes, terminal modules (ps* commands)
appmodules/    # Built-in modules (BrainDump, Cyb3rCollector)
usermodules/   # User scripts and files
file_loaders/  # File type handlers
icons/         # Application icons and assets
```

## License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v3.0.
