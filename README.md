# shell-tunnel

**shell-tunnel** is an ultra-lightweight system gateway designed to enable AI agents to seamlessly control remote terminals via API without the friction of complex infrastructure setup or traditional SSH management.

## Project Introduction

Modern AI agents need to go beyond writing code—they must interact directly with systems to execute commands, debug environments, and solve problems in real-time. **shell-tunnel** removes the burden of heavy SSH authentication and the fragmentation of OS-specific shells. It provides a standardized channel for agents to command any OS terminal using a single **REST/WebSocket API** specification.

## Project Objectives

* **Maximize Agent Connectivity:** Bypass the complexity of SSH key management and provide an immediate, programmable path for agents to access systems.
* **Unified Control Interface:** Provide a consistent command and response structure regardless of whether the target system is Windows (PowerShell/CMD) or Linux (Bash/Zsh).
* **Minimize Operational Overhead:** Distributed as a zero-dependency, single binary that requires near-zero configuration for deployment.

## Roles and Scope

### Key Capabilities (In-Scope)

* **Multi-Platform Shell Abstraction:** Supports Windows ConPTY and Unix PTY to expose full control of interactive programs (e.g., Vim, Top) via API.
* **Real-time Streaming:** Leverages WebSockets to stream terminal output back to the agent with minimal latency.
* **Stateful Session Management:** Manages independent sessions per agent to ensure continuity of working directories (`cd`), environment variables, and process states.

### Constraints (Out-of-Scope)

* Provision of a User GUI (Web terminal interface).
* Complex Multi-user RBAC (Role-Based Access Control).
* Persistent storage of session logs after termination.

## Technical Highlights

### 1. Ultra-lightweight Single Binary (Rust-based)

* **Zero-Dependency:** Operates as a standalone executable without requiring external runtimes like Python or Node.js.
* **Low Resource Consumption:** Optimized for a minimal CPU and memory footprint while idling for agent requests.

### 2. High-Performance OS Integration

* **Native PTY Bridge:** Interfaces directly with native OS terminal engines (ConPTY/PTY) to ensure the lowest possible latency.
* **Unified API:** Standardized JSON schema for sending commands and receiving results across all supported operating systems.

### 3. Built-in Security Layer

* **Token-based Auth:** Uses API token authentication optimized for automated agent integration.
* **Encryption:** Supports secure communication channels to ensure data confidentiality during transit.
* **Command Sandboxing:** Includes features to restrict working directories or blacklist dangerous commands.

### 4. Agent-Centric Interface

* **REST & WebSocket Hybrid:** Supports both discrete command execution (REST) and continuous interactive control (WebSocket).
* **Structured Output:** Returns execution results and exit codes in standardized JSON, removing the parsing burden from the AI agent.