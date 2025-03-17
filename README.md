<h1 align="center">RootShield</h1>
<h3 align="center">v2.0.0</h3>

**RootShield : The Ultimate Shield for Rooted Android Devices** - Protect your rooted Android device from unauthorized file operations and process executions! 🛡️ RootShield is a powerful kernel module that ensures your device remains secure by monitoring and preventing risky activities. Built to safeguard your most critical files and processes, RootShield is your device’s ultimate defense mechanism. 🛠️🔥

## What's New (v2.0.0)

- **Modular Architecture**: Completely redesigned with a modular structure for better maintainability and extensibility.
- **Memory Protection**: New memory monitoring to detect and prevent buffer overflows and code injection attacks.
- **Kernel Module Protection**: Added protection against loading of suspicious or malicious kernel modules.
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

3. Load the RootShield module into your kernel:

   ```bash
   sudo insmod rootshield.ko
   ```

4. To unload the module:

   ```bash
   sudo rmmod rootshield
   ```

5. Monitor the system logs to see RootShield in action:

   ```bash
   dmesg | grep RootShield
   ```

## Disclaimer

🌟🌟🌟 "The developer of **RootShield : The Ultimate Shield for Rooted Android Devices** is not responsible for any misuse or illegal activities conducted with this tool. Use at your own risk." 🌟🌟🌟

### Note

RootShield is a powerful tool designed to protect rooted Android devices. It should only be used for legitimate purposes with proper authorization. Unauthorized use of RootShield or similar tools can lead to violations of privacy and legal issues. Always ensure you have the necessary permissions and adhere to ethical guidelines when using RootShield. Misuse of this tool is illegal and against ethical hacking practices.

## Acknowledgments

**RootShield : The Ultimate Shield for Rooted Android Devices** is developed for educational and research purposes. It is intended to help users and developers secure their devices in a responsible manner. The developer of this tool, @ImKKingshuk, is not liable for any misuse. Contributions are welcome through issue reporting and pull requests!

### 😊 Stay Secure with RootShield! 😊
