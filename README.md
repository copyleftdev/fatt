![FATT Security Scanner](fatt.png)

# FATT (Find All The Things)

A high-performance, modular, asynchronous, and distributed security scanning CLI tool designed to rapidly identify sensitive or exposed files and directories across millions of domains.

## Features

- 🚀 **High Performance**: Built in Rust for maximum speed and efficiency
- 🔄 **Asynchronous**: Leverages Tokio for concurrent scanning operations
- 🌐 **Distributed**: Scales horizontally across multiple worker nodes
- 🧩 **Modular**: Easily extend with custom scanning rules via YAML configuration
- 💾 **Persistent DNS Cache**: Dramatically improves scanning speed for repeat operations
- 📊 **Comprehensive Reporting**: SQLite storage for efficient result management

## Installation

```bash
cargo install fatt
```

Or build from source:

```bash
git clone https://github.com/copyleftdev/fatt.git
cd fatt
cargo build --release
```

## Releases

FATT is available as pre-built binaries for Windows, macOS (Intel and Apple Silicon), and Linux. These binaries are automatically generated through our CI/CD pipeline whenever a new release is tagged.

### Download Pre-built Binaries

Visit the [Releases page](https://github.com/copyleftdev/fatt/releases) to download the latest version for your platform:

- **Windows**: `fatt-windows-amd64.zip`
- **macOS Intel**: `fatt-macos-amd64.tar.gz`
- **macOS Apple Silicon**: `fatt-macos-arm64.tar.gz`
- **Linux**: `fatt-linux-amd64.tar.gz`

Each release package includes the executable, LICENSE file, and rule-examples directory.

### Creating a Release

For maintainers, creating a new release is as simple as pushing a new version tag:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

This will trigger the GitHub Actions workflow that builds and packages FATT for all platforms.

## Quick Start

```bash
# Scan domains from a list using default rules
fatt scan -i domains.txt

# Scan with custom rules
fatt scan -i domains.txt -r custom-rules.yaml

# Export results to CSV
fatt results export -o findings.csv

# Start a worker node for distributed scanning
fatt worker start -m master-ip:port
```

## Configuration

FATT uses YAML-based rules for scan configuration. Example:

```yaml
rules:
  - name: Git Exposure
    path: /.git/HEAD
    signature: "ref: refs/"
  - name: Env File Exposure
    path: /.env
    signature: "APP_KEY="
```

## Rule Examples

FATT includes a comprehensive set of rule examples in the `rule-examples` directory, organized by technology:

- **admin-panels.yaml** - Common admin interfaces and control panels
- **api-endpoints.yaml** - REST API endpoints and documentation resources
- **cloud-service-paths.yaml** - AWS, GCP, Azure, and Kubernetes paths
- **common-paths.yaml** - Comprehensive collection of various path types
- **dangerous-defaults.yaml** - Exposed configs and sensitive files
- **database-paths.yaml** - SQL and NoSQL database management interfaces
- **debug-endpoints.yaml** - Debug, monitoring, and development endpoints
- **ecommerce-webapp-paths.yaml** - eCommerce platforms and web frameworks
- **graphql-endpoints.yaml** - GraphQL endpoints and development tools
- **iot-embedded-paths.yaml** - IoT devices, routers, cameras, and ICS systems
- **java-spring-paths.yaml** - Spring Boot actuators and Java web applications
- **microsoft-paths.yaml** - Microsoft Exchange, SharePoint, and Azure paths

Load specific rule sets for targeted scanning:

```rust
// Use a single category
let rules = rules::load_rules("rule-examples/microsoft-paths.yaml").unwrap();

// Or add rules to your main ruleset
rules::add_rule("rule-examples/database-paths.yaml").unwrap();
```

## Usage

```
USAGE:
    fatt <SUBCOMMAND>

SUBCOMMANDS:
    scan      Scan domains for sensitive files and directories
    rules     Manage scanning rules
    results   Query and export scan results
    dns       Manage DNS cache
    worker    Control distributed worker nodes
    help      Prints help information
```

## Performance Tuning

FATT is designed for high performance but can be further optimized:

- Increase concurrency with `-c/--concurrency` flag
- Adjust batch size with `-b/--batch-size` flag
- Optimize DNS cache lifetime with `--dns-ttl` option

## License

This project is licensed under the HACKFU PUBLIC LICENSE (HFPL) - "Don't Be A Noob" Edition. See the [LICENSE](LICENSE) file for details.

 2025 [copyleftdev](https://github.com/copyleftdev)
