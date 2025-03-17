<h1 align="center">RootShield</h1>
<h3 align="center">v1.1.0</h3>

**RootShield : The Ultimate Shield for Rooted Android Devices** - Protect your rooted Android device from unauthorized file operations and process executions! 🛡️ RootShield is a powerful kernel module that ensures your device remains secure by monitoring and preventing risky activities. Built to safeguard your most critical files and processes, RootShield is your device’s ultimate defense mechanism. 🛠️🔥

## What's New (v1.1.0)

- **Enhanced Security**: Introduced more comprehensive protection mechanisms against unauthorized file writes and process executions.
- **Performance Optimizations**: Optimized kprobe handlers for improved system performance.

## Features

- 🛡️ **Execution Protection**: Monitors and blocks execution of sensitive binaries like `su` on rooted devices.
- 📝 **File Write Protection**: Prevents unauthorized writes to critical directories such as `/dev/block` and `.magisk/block`.
- 🗑️ **File Deletion Protection**: Safeguards important system directories from being unlinked or deleted.
- 📊 **Detailed Logging**: Logs all blocked activities for easy monitoring and auditing.
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

## Features

RootShield v2.0.0 includes comprehensive protection mechanisms:

- **File System Protection**: Guards critical system paths and prevents unauthorized modifications to system files
- **Process Execution Control**: Blocks execution of suspicious binaries and commands
- **Process Manipulation Prevention**: Prevents tampering with system processes and memory injection
- **Network Activity Monitoring**: Detects and blocks connections to suspicious ports commonly used for backdoors
- **System Call Protection**: Monitors sensitive system calls that could be used for privilege escalation
- **Comprehensive Logging**: Detailed security alerts with process information for better threat analysis

## Disclaimer

🌟🌟🌟 "The developer of **RootShield : The Ultimate Shield for Rooted Android Devices** is not responsible for any misuse or illegal activities conducted with this tool. Use at your own risk." 🌟🌟🌟

### Note

RootShield is a powerful tool designed to protect rooted Android devices. It should only be used for legitimate purposes with proper authorization. Unauthorized use of RootShield or similar tools can lead to violations of privacy and legal issues. Always ensure you have the necessary permissions and adhere to ethical guidelines when using RootShield. Misuse of this tool is illegal and against ethical hacking practices.

## Acknowledgments

**RootShield : The Ultimate Shield for Rooted Android Devices** is developed for educational and research purposes. It is intended to help users and developers secure their devices in a responsible manner. The developer of this tool, @ImKKingshuk, is not liable for any misuse. Contributions are welcome through issue reporting and pull requests!

### 😊 Stay Secure with RootShield! 😊
