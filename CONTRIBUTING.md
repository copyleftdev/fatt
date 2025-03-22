# Contributing to FATT

Thank you for your interest in contributing to FATT (Find All The Things)! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report. Following these guidelines helps maintainers understand your report, reproduce the issue, and find related reports.

Before creating bug reports, please check the issue tracker as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots or animated GIFs** which show you following the described steps and clearly demonstrate the problem.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Explain why this enhancement would be useful** to most FATT users.

### Pull Requests

* Fill in the required template
* Follow the Rust style guidelines
* Include appropriate test cases
* Run `cargo fmt` and `cargo clippy` before submitting
* Ensure all tests pass locally before submitting your PR

## Development Workflow

1. Fork the repository
2. Create a new branch: `git checkout -b my-branch-name`
3. Make your changes
4. Run tests: `cargo test`
5. Run linters: `cargo fmt` and `cargo clippy`
6. Submit a pull request

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Rust Styleguide

* Follow the official [Rust style guidelines](https://doc.rust-lang.org/1.0.0/style/README.html)
* Use `cargo fmt` to format your code
* Ensure your code passes `cargo clippy` without warnings

## License

By contributing to FATT, you agree that your contributions will be licensed under the project's license.
