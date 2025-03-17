<h1 align="center">RootShield</h1>
<h3 align="center">v2.0.0</h3>

**RootShield : The Ultimate Shield for Rooted Android Devices** - Protect your rooted Android device from unauthorized file operations and process executions! 🛡️ RootShield is a powerful kernel module that ensures your device remains secure by monitoring and preventing risky activities. Built to safeguard your most critical files and processes, RootShield is your device’s ultimate defense mechanism. 🛠️🔥

## What's New (v2.0.0)

- **Modular Architecture**: Completely redesigned with a modular structure for better maintainability and extensibility.
- **Memory Protection**: New memory monitoring to detect and prevent buffer overflows and code injection attacks.
- **Kernel Module Protection**: Added protection against loading of suspicious or malicious kernel modules.
- **Runtime Configuration**: Dynamic configuration options that can be set when loading the module without recompilation.
- **Security Statistics**: Comprehensive tracking and reporting of security events and blocked threats.
- **Configurable Security Policies**: New configuration options to customize security responses and monitoring scope.
- **Performance Improvements**: Optimized monitoring with conditional compilation for minimal performance impact.

## Features

- 🛡️ **Execution Protection**: Monitors and blocks execution of sensitive binaries like `su` on rooted devices.
- 📝 **File System Protection**: Prevents unauthorized writes and access to critical system paths.
- 🗑️ **Process Protection**: Safeguards against suspicious process creation and manipulation.
- 🌐 **Network Monitoring**: Detects and blocks connections to suspicious ports commonly used for backdoors.
- 🔍 **System Call Protection**: Monitors sensitive system calls that could be used for privilege escalation.
- 💾 **Memory Protection**: Prevents memory-based attacks like buffer overflows and code injection.
- 📦 **Module Loading Protection**: Blocks loading of suspicious kernel modules that might contain malware.
- ⚙️ **Configurable Security Policies**: Customize security responses based on your needs.
- 📊 **Comprehensive Logging**: Detailed security alerts with process information for better threat analysis.
- 🛠️ **Easy to Integrate**: Simple integration as a kernel module with a straightforward setup process.
- 🔄 **Dynamic Module Loading/Unloading**: Easily load and unload the RootShield module as needed.

## Requirements

- **Linux Kernel** (with Kprobes support)
- **Rooted Android Device**
- **GNU Make** for compiling the module
- **Kernel Headers** installed for your Android device

## How to Use

To secure your Android device with **RootShield**, follow these steps:

1. Clone the repository and navigate to the project directory:

   ```bash
   git clone https://github.com/ImKKingshuk/RootShield.git
   cd RootShield
   ```

2. Build the kernel module:

   ```bash
   make
   ```

3. Load the RootShield module into your kernel with default settings:

   ```bash
   sudo insmod rootshield.ko
   ```

   Or customize the security settings at load time:

   ```bash
   sudo insmod rootshield.ko exec_monitor_enabled=1 file_monitor_enabled=1 notify_only=1
   ```

4. Build and run the notification client (optional):

   ```bash
   cd client
   make
   sudo ./rootshield_client
   ```

5. To unload the module:

   ```bash
   sudo rmmod rootshield
   ```

6. Monitor the system logs to see RootShield in action:

   ```bash
   dmesg | grep RootShield
   ```

## Runtime Configuration Options

RootShield supports the following configuration options that can be set when loading the module:

| Option                  | Type | Default | Description                                   |
| ----------------------- | ---- | ------- | --------------------------------------------- |
| exec_monitor_enabled    | bool | 1       | Enable/disable execution monitoring           |
| file_monitor_enabled    | bool | 1       | Enable/disable file system monitoring         |
| process_monitor_enabled | bool | 1       | Enable/disable process monitoring             |
| network_monitor_enabled | bool | 1       | Enable/disable network monitoring             |
| syscall_monitor_enabled | bool | 1       | Enable/disable syscall monitoring             |
| memory_monitor_enabled  | bool | 1       | Enable/disable memory monitoring              |
| module_monitor_enabled  | bool | 1       | Enable/disable kernel module monitoring       |
| kill_violating_process  | bool | 1       | Kill processes that violate security policies |
| notify_only             | bool | 0       | Only log violations without taking action     |
| block_only              | bool | 0       | Block operations without killing the process  |
| verbose_logging         | bool | 0       | Enable verbose logging for debugging          |

## Troubleshooting

Here are some common issues and their solutions:

### Module Loading Issues

- **Error: "Module not found"**

  - Ensure you're in the correct directory
  - Verify the module was built successfully
  - Check kernel version compatibility

- **Error: "Required key not available"**
  - Your kernel may require signed modules
  - Check your device's secure boot settings

### Runtime Issues

- **High CPU Usage**

  - Disable verbose logging
  - Adjust monitoring scope in configuration
  - Update to the latest version

- **System Slowdown**
  - Reduce the number of enabled monitors
  - Set `block_only=1` instead of killing processes
  - Consider using `notify_only=1` for testing

## Development Guide

### Project Structure

```
src/
  ├── core/           # Core functionality
  ├── include/        # Header files
  ├── monitors/       # Individual monitoring modules
  └── utils/          # Utility functions
```

### Adding New Features

1. Create a new monitor in `src/monitors/`
2. Define the monitor's interface in `include/`
3. Register the monitor in `src/core/main.c`
4. Add configuration options in `include/config.h`

### Coding Standards

- Follow the Linux kernel coding style
- Add comprehensive comments and documentation
- Include unit tests for new features
- Maintain backward compatibility

## Security Best Practices

### Configuration

- Start with `notify_only=1` to understand impact
- Enable all monitoring features in production
- Use `verbose_logging=1` only for debugging
- Regularly update RootShield to latest version

### System Integration

- Monitor system logs regularly
- Set up automated alerts for violations
- Maintain backups before major changes
- Test thoroughly in staging environment

### Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

GNU General Public License v3.0
