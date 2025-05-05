# Sharingan File Monitor

![Sharingan Logo](https://img.shields.io/badge/Sharingan-File%20Monitor-red?style=for-the-badge&logo=github)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://en.wikipedia.org/wiki/Linux)

          ![3-tomoe](https://github.com/user-attachments/assets/bab040fb-1602-45b0-b32c-90c59691ae71)

A comprehensive Linux file system monitoring tool that combines both inotify and fanotify subsystems to track file activities across your system. Named after the famous Sharingan eye of the Uchihaclan from Naruto.

## Features

- **Dual Monitoring Systems**: Leverages both inotify and fanotify Linux subsystems
- **Process Tracking**: Identifies which processes are responsible for file operations
- **Comprehensive Event Detection**: Tracks file creation, deletion, modification, access, and more
- **Real-time Visualization**: Displays file activities in a colored table format in real-time
- **JSON Export**: Logs all events to JSON files for further analysis
- **Customizable Monitoring**: Configure which paths to monitor or exclude
- **Low Overhead**: Designed to minimize system performance impact

## Use Cases

- **Dynamic Malware Analysis**: Monitor file system changes during malware execution
- **System Behavior Analysis**: Understand how applications interact with your file system
- **Debugging File Access**: Troubleshoot applications by monitoring their file operations

## System Requirements

- Linux kernel 2.6.37 or higher (for fanotify support)
- C++17 compatible compiler (GCC 7+ or Clang 5+)
- CMake 3.10 or higher
- nlohmann_json library (version 3.9.1 or higher)
- Sufficient inotify watch limits (adjustable via sysctl)
- Root privileges for fanotify operation

## Installation

### Installing Dependencies

#### Debian/Ubuntu/Kali Linux:
```bash
sudo apt update
sudo apt install build-essential cmake nlohmann-json3-dev
```

#### Fedora/RHEL/CentOS:
```bash
sudo dnf install gcc-c++ cmake nlohmann-json-devel
```

#### Arch Linux:
```bash
sudo pacman -S base-devel cmake nlohmann-json
```

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/thebinaryhashira/SharinganFilemonitor.git
cd sharingan-file-monitor
```

2. Create a build directory and compile:
```bash
mkdir build
cd build
cmake ..
make
```

3. The executable will be created in the project's root directory.

4. Verify the installation:
```bash
cd ..
./sharingan_file_monitor --help
```

## Configuration

Copy the example configuration file if needed:
```bash
cp config.json.example config.json
```

Edit the configuration file to customize monitoring behavior:
```bash
nano config.json
```

### Configuration File Format

The configuration file uses JSON format:
```json
{
    "excluded_paths": [
        "/proc",
        "/sys",
        "/run"
    ],
    "output_file": "malware_file_activity.json",
    "monitor_own_events": false
}
```

## Usage

### Basic Usage

Run Sharingan File Monitor with default settings:
```bash
sudo ./sharingan_file_monitor
```

This will monitor the /home directory and record events to a timestamped JSON file in the current directory.

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-p, --path PATH` | Specify the directory to monitor (default: /home) |
| `-c, --config PATH` | Specify the path to a configuration file (default: config.json) |
| `-h, --help` | Display help information |

Example with command-line options:
```bash
sudo ./sharingan_file_monitor -p /var/www -c /etc/sharingan/custom_config.json
```

## Understanding the Output

### Console Output

Sharingan File Monitor displays real-time file activity in a table format with the following columns:
- Timestamp: Date and time when the event occurred
- Event Type: Type of file operation (CREATE, DELETE, MODIFY, etc.)
- PID: Process ID responsible for the event
- Process Name: Name of the process that triggered the event
- Path: Full path to the file or directory involved

Event types are color-coded for easier identification:
- Green: OPEN events
- Red: DELETE events
- Yellow: MODIFY or CLOSE_WRITE events
- Blue: ACCESS events
- Cyan: CREATE events
- Magenta: MOVED_FROM or MOVED_TO events

### JSON Output Files

All events are logged to a JSON file with a timestamped name (e.g., `malware_file_activity_2023-04-21_120000.json`). The JSON format contains the following information for each event:

```json
{
    "path": "/path/to/file",
    "event_type": "MODIFY",
    "timestamp": 1713799200,
    "pid": 1234,
    "process_name": "application"
}
```

## Performance Considerations

### Inotify Watch Limits

Linux imposes a limit on the number of inotify watches. If you're monitoring many directories, you may need to increase this limit:

```bash
# Check current limit
cat /proc/sys/fs/inotify/max_user_watches

# Increase the limit temporarily
sudo sysctl fs.inotify.max_user_watches=524288

# Make it permanent
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Monitoring Large Directories

When monitoring large directory structures:
1. Be selective about which directories to monitor
2. Use appropriate exclusion patterns
3. Consider monitoring specific subdirectories instead of entire filesystems
4. Be aware of the impact on system resources, especially when monitoring busy directories

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "FAILED TO INITIALIZE FANOTIFY" | Run with sudo or set appropriate capabilities |
| "INOTIFY WATCH LIMIT REACHED" | Increase the inotify watch limit as described in Performance Considerations |
| HIGH CPU OR MEMORY USAGE | Add more paths to excluded_paths in the configuration file |
| "FAILED TO OPEN OUTPUT FILE" | Check permissions in the current directory |
| NO EVENTS BEING LOGGED | Verify the monitored path exists and is accessible |

### Enabling Debug Output

For more detailed output, you can compile with debug symbols enabled:
```bash
cd build
cmake -DDEBUG_BUILD=ON ..
make
cd ..
```

## Frequently Asked Questions

**Q: Can I run Sharingan File Monitor without root privileges?**  
A: No, the fanotify module requires root privileges.

**Q: How can I reduce the number of events logged?**  
A: Add more directories to the excluded_paths array in the configuration file.

**Q: How much disk space do the log files use?**  
A: This depends on the activity level of your system and which directories you monitor. For busy systems, consider implementing log rotation or filtering.

**Q: Can I use Sharingan File Monitor for malware detection?**  
A: Yes, this is one of its primary use cases. Look for suspicious file patterns, unexpected executable creations, or modifications to system files.

**Q: Does it impact system performance?**  
A: There is some overhead, but it's generally minimal on modern systems. The impact increases with the number of directories monitored and the level of file activity.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The name Inspired by the Sharingan eye from Naruto, which provides enhanced perception
- Thanks to the Linux kernel team for the powerful inotify and fanotify APIs
- Built with nlohmann's JSON library

## Author

- **Samora Tandon** - [thebinaryhashira](https://github.com/thebinaryhashira)
  - Twitter: [@tandon_samora](https://x.com/tandon_samora)
  - LinkedIn: [Tandon Samora](https://www.linkedin.com/in/tandon-samora-98244b23b/)
