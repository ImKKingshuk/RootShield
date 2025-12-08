<h1 align="center">RootShield</h1>
<h3 align="center">v3.0.0 - The Ultimate Kernel Security Module</h3>

**RootShield : The Ultimate Shield for Rooted Android Devices & Linux Systems** - Advanced kernel-level security with comprehensive monitoring, behavioral analysis, and enterprise-grade protection! 🛡️ RootShield v3.0 is a revolutionary security module that transforms your device into an impenetrable fortress. Built with cutting-edge technology, it provides multi-layered protection against sophisticated attacks. 🛠️🔥🤖



## Features Status Legend

| Tag | Meaning |
|-----|---------|
| ✅ | **Fully Working** - Feature is complete and operational |
| 🔧 | **Functional** - Core functionality works, with some limitations |
| 🚧 | **Coming Soon** - Placeholder/under development |

---

## Core Security Monitors ✅

### 🛡️ Execution Protection ✅
- **Binary Execution Monitoring** ✅: Intercepts `do_execveat_common` via kprobe
- **Suspicious Command Detection** ✅: Blocks su, busybox, tcpdump, strace, frida
- **Process Termination** ✅: Kills violating processes on detection
- **Event Notification** ✅: Sends alerts to userspace via Netlink

### 📝 File System Protection ✅
- **Write Monitoring** ✅: kprobe on `vfs_write` for protected paths
- **Open Monitoring** ✅: kprobe on `vfs_open` for sensitive files
- **Protected Paths** ✅: /dev/block, /system/bin, /proc/kallsyms, /proc/kcore
- **Access Control** ✅: Blocks unauthorized root process access

### 🗑️ Process Protection ✅
- **File Deletion Monitoring** ✅: Protects critical system paths via `do_unlinkat`
- **Fork Monitoring** ✅: Detects suspicious process creation patterns
- **Ptrace Protection** ✅: Prevents memory injection attempts
- **Anti-Tampering** ✅: Blocks code injection via ptrace

### 🌐 Network Monitoring ✅
- **Outgoing Traffic Analysis** ✅: Netfilter hook on `NF_INET_LOCAL_OUT`
- **Suspicious Port Blocking** ✅: Blocks 1337, 4444, 5555, 31337, 12345
- **TCP/UDP Inspection** ✅: Analyzes both protocols
- **Root Process Filtering** ✅: Monitors only elevated processes

### 🔍 System Call Protection ✅
- **Sensitive Syscall Monitoring** ✅: ptrace, capset, mount, init_module
- **kprobe Intercepts** ✅: Multiple syscall hooks
- **Suspicious Process Detection** ✅: Identifies malicious syscall patterns
- **Real-Time Blocking** ✅: Terminates violating processes

### 💾 Memory Protection ✅
- **Large Allocation Detection** ✅: Flags allocations over 10MB
- **Executable Memory Monitoring** ✅: Detects `set_memory_x` calls
- **Buffer Overflow Detection** ✅: Identifies suspicious memory patterns
- **Code Injection Prevention** ✅: Blocks attempts to make memory executable

### 📦 Module Loading Protection ✅
- **Module Loading Intercept** ✅: kprobe on `load_module`
- **Suspicious Name Detection** ✅: Blocks "hide", "root", "hack", "inject"
- **Real-Time Alerts** ✅: Immediate notification on detection

---

## Advanced Security Features ✅

### 🧠 AI Behavioral Analysis ✅
- **Statistical Modeling** ✅: Mean, variance, standard deviation tracking
- **Z-Score Anomaly Detection** ✅: Configurable threshold (default: 3.0)
- **Sliding Window Analysis** ✅: Time-based behavior profiling
- **Per-Process Profiling** ✅: Individual process behavior tracking
- **Global Baseline** ✅: System-wide anomaly detection
- **Feature Extraction** ✅: Syscall frequency, process spawn rate, file access, network connections

### 🔍 Anti-Rootkit Engine ✅
- **Hidden Module Detection** ✅: Cross-references module list
- **Syscall Hook Detection** ✅: Identifies syscall table modifications
- **Hidden Process Detection** ✅: Task list vs /proc comparison
- **Memory Integrity Checking** ✅: Verifies critical memory regions
- **IDT Integrity Verification** ✅: Detects interrupt table manipulation
- **Periodic Scanning** ✅: Automated background checks

### 🛡️ Self-Protection ✅
- **Module Locking** ✅: Prevents forced unloading (`try_module_get`)
- **SHA-256 Integrity Hashing** ✅: Code section verification
- **Integrity Monitoring** ✅: Continuous integrity checks
- **Tamper Detection** ✅: Identifies modification attempts
- **Protection Levels** ✅: BASIC, STANDARD, HIGH, MAXIMUM
- **Emergency Mode** ✅: Lockdown on severe threats

---

## Infrastructure & Architecture ✅

### 📡 Event System ✅
- **Publish-Subscribe Pattern** ✅: Inter-component event communication
- **Circular Buffer Queue** ✅: High-performance event storage (256 events)
- **Async Dispatch** ✅: Workqueue-based processing
- **Event Filtering** ✅: Type, severity, source-based filtering
- **Statistics Tracking** ✅: Total/processed/dropped event metrics

### 📋 Rule Engine ✅
- **Red-Black Tree Storage** ✅: Fast rule lookup and management
- **Priority-Based Evaluation** ✅: Higher priority rules evaluated first
- **Condition System** ✅: Process name, file path, UID, network, syscall conditions
- **Operators** ✅: Equals, contains, starts_with, ends_with, greater_than, less_than
- **Dynamic Rule Loading** ✅: Runtime rule addition/removal
- **Rule Statistics** ✅: Hit counts, evaluation times

### 🔌 Plugin System ✅
- **Dynamic Registration** ✅: Load/unload plugins at runtime
- **Lifecycle Management** ✅: Init, start, stop, exit states
- **Dependency Resolution** ✅: Automatic dependency checking
- **Event Broadcasting** ✅: Plugin-to-plugin communication
- **Configuration API** ✅: Key-value plugin configuration
- **Health Monitoring** ✅: Plugin health checks and statistics

---

## Management & Monitoring ✅

### 🌐 REST API ✅
- **GET /api/v1/status** ✅: System status and version
- **GET /api/v1/events** ✅: Security events retrieval
- **GET/POST /api/v1/rules** ✅: Rule management
- **GET /api/v1/plugins** ✅: Plugin status
- **GET /api/v1/statistics** ✅: Security statistics
- **SQLite Backend** ✅: Persistent storage
- **JSON Responses** ✅: REST-compliant API

### 📊 Real-Time Client ✅
- **Netlink Communication** ✅: Kernel to userspace notifications
- **Colored Output** ✅: Red (violations), yellow (blocked), blue (stats)
- **Live Event Feed** ✅: Real-time security event display
- **Process Information** ✅: PID, process name, path details

### 🖥️ CLI Tool ✅
- **Status Command** ✅: System status overview
- **Events Command** ✅: Recent events with limit support
- **Rules Command** ✅: List and create security rules
- **Plugins Command** ✅: Active plugin listing
- **Stats Command** ✅: Security statistics display
- **HTTP Client** ✅: libcurl-based API communication
- **JSON Parsing** ✅: json-c based response parsing

### 📈 Statistics & Reporting ✅
- **Per-Monitor Counters** ✅: Violations and blocks per monitor
- **Atomic Operations** ✅: Thread-safe statistics
- **Real-Time Updates** ✅: Live statistics tracking
- **Reset Capability** ✅: Statistics reset functionality

---

## Planned Features 🚧

### 🔐 Hardware-Assisted Security 🚧
- **TPM Integration** 🚧: Trusted Platform Module support
- **Secure Boot Verification** 🚧: Boot integrity checking
- **Hardware Key Storage** 🚧: Cryptographic key protection

### 🌐 Enterprise Features 🚧
- **Multi-Tenant Support** 🚧: Role-based access control
- **Compliance Reporting** 🚧: Automated compliance checks
- **Multi-Device Management** 🚧: Centralized orchestration
- **Web Dashboard** 🚧: Modern web interface

## Requirements

- **Linux Kernel** (4.15+ with Kprobes and Netfilter support)
- **Rooted Android Device** (or Linux system with root access)
- **GNU Make** and build tools
- **Kernel Headers** for target kernel version
- **SQLite3** for database backend (API server)
- **libmicrohttpd** and **json-c** for API server
- **GCC** with C11 support

## Quick Start

### 1. Build Everything

```bash
git clone https://github.com/ImKKingshuk/RootShield.git
cd RootShield
make deps-check  # Check dependencies
make all         # Build kernel module and API server
```

### 2. Install and Load

```bash
sudo make install    # Install all components
# Or manually:
sudo insmod rootshield.ko
```

### 3. Start Userspace Components

```bash
# Start the notification client to receive alerts
./client/rootshield_client

# Start the API server (requires libmicrohttpd, json-c, sqlite3)
./api/rootshield_api
```

### 4. Access API

The API server listens on `http://localhost:8080`. Available endpoints:
- `GET /api/v1/status` - System status
- `GET /api/v1/events` - Security events
- `GET/POST /api/v1/rules` - Security rules management
- `GET /api/v1/plugins` - Plugin status
- `GET /api/v1/statistics` - Security statistics

### 5. Basic Usage

```bash
# Load with default configuration
sudo insmod rootshield.ko

# Load with custom configuration
sudo insmod rootshield.ko exec_monitor_enabled=1 file_monitor_enabled=1 verbose_logging=1

# Monitor system logs
dmesg | grep RootShield

# View module parameters
cat /sys/module/rootshield/parameters/*
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    RootShield v3.0                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │              API Server (Port 8080)                 │    │
│  │  ┌─────────────────────────────────────────────┐   │    │
│  │  │        REST API (libmicrohttpd)             │   │    │
│  │  │     SQLite Database | JSON Responses        │   │    │
│  │  └─────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │            User Space Components                    │    │
│  │  ┌─────────────────┐ ┌─────────────────────────┐   │    │
│  │  │   Notification  │ │     Web Dashboard       │   │    │
│  │  │   Client        │ │     (Coming Soon)       │   │    │
│  │  │   (Netlink)     │ │                         │   │    │
│  │  └─────────────────┘ └─────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │             Kernel Space Module                     │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │    │
│  │  │  Core   │ │Notific- │ │ Runtime │ │ Stats   │   │    │
│  │  │ Engine  │ │  ation  │ │ Config  │ │ Tracker │   │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │    │
│  │                                                     │    │
│  │  ┌─────────────────────────────────────────────┐   │    │
│  │  │             Security Monitors               │   │    │
│  │  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐   │   │    │
│  │  │  │Exec │ │File │ │Proc │ │Net  │ │Sys- │   │   │    │
│  │  │  │Mon  │ │Mon  │ │Mon  │ │Mon  │ │call │   │   │    │
│  │  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘   │   │    │
│  │  │  ┌─────┐ ┌─────┐                           │   │    │
│  │  │  │Mem  │ │Mod  │                           │   │    │
│  │  │  │Mon  │ │Mon  │                           │   │    │
│  │  │  └─────┘ └─────┘                           │   │    │
│  │  └─────────────────────────────────────────────┘   │    │
│  │                                                     │    │
│  │  ┌─────────────────────────────────────────────┐   │    │
│  │  │            Advanced Plugins                 │   │    │
│  │  │  ┌───────────────┐ ┌───────────────────┐   │   │    │
│  │  │  │  Anti-Rootkit │ │ Behavioral        │   │   │    │
│  │  │  │  (Partial)    │ │ Analyzer          │   │   │    │
│  │  │  └───────────────┘ └───────────────────┘   │   │    │
│  │  └─────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                     Hardware/Kernel                         │
│    Kprobes | Netfilter | Netlink | proc/sys interfaces      │
└─────────────────────────────────────────────────────────────┘
```

## API Documentation

### REST Endpoints

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/api/v1/status` | GET | System status | ✅ Implemented |
| `/api/v1/events` | GET | Security events | ✅ Implemented |
| `/api/v1/rules` | GET | List security rules | ✅ Implemented |
| `/api/v1/rules` | POST | Create new rule | ✅ Implemented |
| `/api/v1/plugins` | GET | Plugin status | ✅ Implemented |
| `/api/v1/statistics` | GET | Security statistics | ✅ Implemented |

### CLI Tool *(Coming Soon)*

```bash
rootshield_cli status                    # System status
rootshield_cli events [limit]           # View recent events
rootshield_cli rules list               # List active rules
rootshield_cli rules add <json>         # Add new rule
rootshield_cli plugins                  # List loaded plugins
rootshield_cli config get <key>         # Get configuration
rootshield_cli config set <key> <value> # Set configuration
```

## Configuration Options

### Kernel Module Parameters

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `exec_monitor_enabled` | bool | true | Enable/disable execution monitoring |
| `file_monitor_enabled` | bool | true | Enable/disable file system monitoring |
| `process_monitor_enabled` | bool | true | Enable/disable process monitoring |
| `network_monitor_enabled` | bool | true | Enable/disable network monitoring |
| `syscall_monitor_enabled` | bool | true | Enable/disable syscall monitoring |
| `memory_monitor_enabled` | bool | true | Enable/disable memory monitoring |
| `module_monitor_enabled` | bool | true | Enable/disable kernel module monitoring |
| `kill_violating_process` | bool | true | Kill processes that violate security policies |
| `notify_only` | bool | false | Only log violations without taking action |
| `block_only` | bool | false | Block operations without killing the process |
| `verbose_logging` | bool | false | Enable verbose logging for debugging |

### Runtime Configuration Notes

- Parameters can be set at module load time: `insmod rootshield.ko verbose_logging=1`
- Parameters are exposed via sysfs: `/sys/module/rootshield/parameters/`
- Security policy validation ensures no conflicting options

## Security Best Practices

### Deployment

- Start with `notify_only=1` for testing and tuning
- Enable verbose logging initially for monitoring false positives
- Monitor system logs and adjust protected paths as needed
- Regular backup of configurations and logs

### Operations

- Use the netlink client for real-time monitoring
- Set up log aggregation for security events
- Regular security audits based on collected statistics
- Keep system and RootShield updated

## Troubleshooting

### Common Issues

**Module Loading Fails**

```bash
# Check kernel version compatibility
uname -r
# Verify kernel headers
ls /lib/modules/$(uname -r)/build
# Check dmesg for detailed errors
dmesg | tail -50
# Check if kprobes are enabled
cat /proc/kallsyms | head
```

**High CPU Usage**

```bash
# Disable verbose logging
sudo insmod rootshield.ko verbose_logging=0
# Disable specific monitors that may be too aggressive
sudo insmod rootshield.ko syscall_monitor_enabled=0
```

**API Server Issues**

```bash
# Check if port is available
netstat -tlnp | grep 8080
# Verify dependencies
ldd api/rootshield_api
# Check API server logs
./api/rootshield_api 2>&1
# Ensure database directory exists
mkdir -p /var/lib/rootshield
```

**Netlink Client Connection Issues**

```bash
# Ensure module is loaded first
lsmod | grep rootshield
# Check dmesg for netlink socket errors
dmesg | grep "RootShield.*netlink"
```



## License

GNU General Public License v3.0

**RootShield v3.0** - Transforming security through innovation, intelligence, and uncompromising protection. 🛡️🤖🔥
