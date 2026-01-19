# Sus Repo Finder 🔍🦀

A Rust monorepo for detecting suspicious code patterns in crates.io packages. The system helps the Rust community identify potentially malicious or risky build-time code in crates before depending on them.

## Overview

Sus Repo Finder consists of two main applications:

1. **Crawler** (`sus-crawler`): Periodically scans crates.io to inspect `build.rs` files and proc-macro crates for suspicious code patterns
2. **Dashboard** (`sus-dashboard`): A read-only web interface displaying findings with severity levels, code snippets, and historical tracking

## Features

### Pattern Detection

The system detects various suspicious patterns including:

- 🌐 **Network calls**: reqwest, std::net, hyper, curl bindings
- 📁 **File system access**: Operations outside expected paths
- 💻 **Shell commands**: std::process::Command, bash/sh invocation
- 🔄 **Process spawning**: Code that could execute arbitrary processes
- 🔑 **Environment variable access**: Especially sensitive credentials
- 📚 **Dynamic library loading**: libloading, dlopen usage
- ⚠️ **Unsafe blocks**: Large or suspicious unsafe code
- 📥 **Build-time downloads**: Fetching binaries during build
- 🔒 **Sensitive path access**: ~/.ssh, ~/.aws, credentials
- 🔐 **Obfuscation**: Base64/hex decoding, encoded strings
- 🔧 **Compiler flag manipulation**: Suspicious cargo outputs
- 🏭 **Macro code generation**: Proc-macros that write files

### Severity Classification

Findings are classified into three severity levels:

- 🔴 **High**: Potentially malicious behavior (sensitive file access, credential theft patterns)
- 🟠 **Medium**: Suspicious but possibly legitimate (network calls, shell commands)
- 🟡 **Low**: Worth noting but commonly benign (unsafe blocks, env access)

### Crawler Features

- Parallel processing (up to 10 crates concurrently)
- Rate limiting and politeness delays
- Incremental crawling (only new/updated crates)
- Checkpoint/resume system for crash recovery
- Live status portal with SSE updates
- Error tracking and retry logic

### Dashboard Features

- Summary statistics and interesting facts
- Searchable crate list with filters
- Detailed crate view with code snippets
- Syntax-highlighted Rust code
- Version comparison and historical tracking
- Direct links to source in repositories

## Technology Stack

- **Backend**: Rust with Tokio async runtime, Axum framework
- **Database**: SQLite with sqlx
- **Frontend**: htmx with server-rendered HTML templates
- **Styling**: Tailwind CSS (dark mode by default)
- **AST Parsing**: syn crate for Rust analysis

## Project Structure

```
sus-repo-finder/
├── Cargo.toml              # Workspace configuration
├── sus-core/               # Shared database models, queries, types
├── sus-detector/           # Pattern detection logic
├── sus-crawler/            # Crawler application with web portal
├── sus-dashboard/          # Read-only findings dashboard
├── data/                   # SQLite database storage
└── init.sh                 # Development environment setup
```

## Prerequisites

- Rust toolchain (rustup with stable channel)
- SQLite3
- Node.js (for Tailwind CSS build)

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd sus-repo-finder
   ```

2. Run the setup script:
   ```bash
   ./init.sh
   ```

3. Start the crawler:
   ```bash
   cargo run -p sus-crawler
   ```
   Open http://localhost:3001 for the crawler portal

4. Start the dashboard (in another terminal):
   ```bash
   cargo run -p sus-dashboard
   ```
   Open http://localhost:3000 for the dashboard

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:./data/sus-repo-finder.db` | SQLite database path |
| `CRAWLER_PORT` | `3001` | Crawler portal port |
| `DASHBOARD_PORT` | `3000` | Dashboard port |
| `RATE_LIMIT_MS` | `1000` | Delay between crates.io requests |
| `MAX_CONCURRENT` | `10` | Maximum parallel crate processing |

## API Endpoints

### Dashboard API

- `GET /api/stats` - Summary statistics
- `GET /api/crates` - List crates with filters and pagination
- `GET /api/crates/:name` - Crate detail with versions
- `GET /api/crates/:name/versions/:version` - Version detail with findings
- `GET /api/crates/:name/compare` - Version comparison data
- `GET /api/findings/recent` - Recent findings

### Crawler Portal API

- `GET /api/crawler/status` - Current crawler status
- `GET /api/crawler/stats` - Crawler statistics
- `GET /api/crawler/queue` - Queue status
- `GET /api/crawler/errors` - Recent errors
- `GET /api/crawler/logs` - SSE endpoint for live logs
- `POST /api/crawler/pause` - Pause crawler
- `POST /api/crawler/resume` - Resume crawler

## Development

### Running Tests

```bash
cargo test --all-features
```

### Code Quality

```bash
cargo fmt --all          # Format code
cargo clippy --all-targets --all-features -- -D warnings  # Lint
```

### Building for Release

```bash
cargo build --release
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  sus-crawler    │     │  sus-dashboard  │
│                 │     │                 │
│ - Fetch crates  │     │ - View findings │
│ - Analyze code  │     │ - Search/filter │
│ - Store results │     │ - Compare vers. │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │   ┌───────────────┐   │
         └───┤  sus-core     ├───┘
             │               │
             │ - DB models   │
             │ - Queries     │
             │ - Types       │
             └───────┬───────┘
                     │
         ┌───────────┴───────────┐
         │    sus-detector       │
         │                       │
         │ - Pattern detection   │
         │ - AST parsing         │
         │ - Severity rating     │
         └───────────────────────┘
```

## License

[Your license here]

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting a pull request.

## Security

If you discover a security vulnerability, please report it responsibly.
