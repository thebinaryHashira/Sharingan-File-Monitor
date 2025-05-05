#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <memory>
#include <filesystem>
#include <functional>

// Linux specific headers
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

// JSON library
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

// Class for handling configuration
class ConfigManager {
private:
    std::vector<std::string> excludedPaths;
    std::string outputFile;
    bool monitorOwnEvents;

public:
    ConfigManager(const std::string& configPath = "config.json") {
        try {
            // Open and parse the config file
            std::ifstream configFile(configPath);
            if (!configFile.is_open()) {
                throw std::runtime_error("Failed to open config file: " + configPath);
            }

            json config;
            configFile >> config;
            
            // Extract excluded paths
            if (config.contains("excluded_paths") && config["excluded_paths"].is_array()) {
                for (const auto& path : config["excluded_paths"]) {
                    excludedPaths.push_back(path);
                }
            }

            // Extract output file
            if (config.contains("output_file") && config["output_file"].is_string()) {
                outputFile = config["output_file"];
            } else {
                outputFile = "malware_file_activity.json"; // Default
            }

            // Extract monitor own events flag
            if (config.contains("monitor_own_events") && config["monitor_own_events"].is_boolean()) {
                monitorOwnEvents = config["monitor_own_events"];
            } else {
                monitorOwnEvents = false; // Default
            }

            std::cout << "Configuration loaded successfully." << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Error loading configuration: " << e.what() << std::endl;
            std::cerr << "Using default configuration." << std::endl;
            
            // Set default configuration
            excludedPaths = {"/proc", "/sys", "/run"};
            outputFile = "malware_file_activity.json";
            monitorOwnEvents = false;
        }
    }

    // Getters
    const std::vector<std::string>& getExcludedPaths() const {
        return excludedPaths;
    }

    const std::string& getOutputFile() const {
        return outputFile;
    }

    bool shouldMonitorOwnEvents() const {
        return monitorOwnEvents;
    }

    // Check if a path should be excluded
    bool isPathExcluded(const std::string& path) const {
        // Check if the path contains the current output file to avoid self-monitoring
        if (path.find(outputFile) != std::string::npos) {
            return true;
        }

        for (const auto& excludedPath : excludedPaths) {
            // Check if the path starts with the excluded path
            if (path.find(excludedPath) == 0) {
                return true;
            }
        }
        return false;
    }

    // Print configuration for debugging
    void printConfig() const {
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Output File: " << outputFile << std::endl;
        std::cout << "  Monitor Own Events: " << (monitorOwnEvents ? "Yes" : "No") << std::endl;
        std::cout << "  Excluded Paths:" << std::endl;
        for (const auto& path : excludedPaths) {
            std::cout << "    - " << path << std::endl;
        }
    }
};

// Process information retrieval
class ProcessMonitor {
private:
    // Cache of process info to avoid repeated lookups
    std::map<pid_t, std::string> processNameCache;
    std::mutex cacheMutex;

    // Read file content as string
    std::string readFileAsString(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return "";
        }
        
        return std::string(std::istreambuf_iterator<char>(file), 
                          std::istreambuf_iterator<char>());
    }

    // Read link target as string
    std::string readLinkAsString(const std::string& path) {
        char buffer[PATH_MAX];
        ssize_t len = readlink(path.c_str(), buffer, sizeof(buffer) - 1);
        if (len == -1) {
            return "";
        }
        buffer[len] = '\0';
        return std::string(buffer);
    }

public:
    // Get process name from PID
    std::string getProcessName(pid_t pid) {
        // Check cache first
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = processNameCache.find(pid);
            if (it != processNameCache.end()) {
                return it->second;
            }
        }

        // Try to get process name from /proc/[pid]/comm
        std::string commPath = "/proc/" + std::to_string(pid) + "/comm";
        std::string name = readFileAsString(commPath);
        
        // Remove trailing newline if present
        if (!name.empty() && name.back() == '\n') {
            name.pop_back();
        }
        
        // If comm file doesn't exist or is empty, try /proc/[pid]/exe
        if (name.empty()) {
            std::string exePath = "/proc/" + std::to_string(pid) + "/exe";
            std::string exe = readLinkAsString(exePath);
            
            if (!exe.empty()) {
                size_t slashPos = exe.find_last_of('/');
                if (slashPos != std::string::npos) {
                    name = exe.substr(slashPos + 1);
                } else {
                    name = exe;
                }
            } else {
                // If all else fails
                name = "Unknown";
            }
        }
        
        // Cache the result
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            processNameCache[pid] = name;
        }
        
        return name;
    }
};

// Define file event structure
struct FileEvent {
    std::string path;
    std::string eventType;
    time_t timestamp;
    pid_t pid;
    std::string processName;
    
    // Convert to JSON
    json toJson() const {
        return json{
            {"path", path},
            {"event_type", eventType},
            {"timestamp", timestamp},
            {"pid", pid},
            {"process_name", processName}
        };
    }
};

// Event logger class
class EventLogger {
private:
    std::string outputFilePath;
    std::ofstream outputFile;
    std::vector<FileEvent> eventBuffer;
    std::mutex eventMutex;
    bool consoleOutputEnabled;
    
    // Column widths for table output
    const int timestampWidth = 20;
    const int eventTypeWidth = 12;
    const int pidWidth = 8;
    const int processNameWidth = 20;
    const int pathWidth = 0; // 0 means don't truncate

    // ANSI color codes
    const std::string colorReset = "\033[0m";
    const std::string colorRed = "\033[31m";
    const std::string colorGreen = "\033[32m";
    const std::string colorYellow = "\033[33m";
    const std::string colorBlue = "\033[34m";
    const std::string colorMagenta = "\033[35m";
    const std::string colorCyan = "\033[36m";
    
    // Format timestamp
    std::string formatTimestamp(time_t timestamp) {
        char buffer[32];
        struct tm* timeinfo = localtime(&timestamp);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buffer);
    }
    
    // Truncate string with ellipsis if too long
    std::string truncateString(const std::string& str, size_t maxLength) {
        if (maxLength == 0 || str.length() <= maxLength) {
            return str;
        }
        
        return str.substr(0, maxLength - 3) + "...";
    }
    
    // Get color for event type
    std::string getColorForEventType(const std::string& eventType) {
        if (eventType == "OPEN") {
            return colorGreen;
        } else if (eventType == "DELETE") {
            return colorRed;
        } else if (eventType == "MODIFY" || eventType == "CLOSE_WRITE") {
            return colorYellow;
        } else if (eventType == "ACCESS") {
            return colorBlue;
        } else if (eventType == "CREATE") {
            return colorCyan;
        } else if (eventType == "MOVED_FROM" || eventType == "MOVED_TO") {
            return colorMagenta;
        } else {
            return "";
        }
    }
    
    // Print horizontal line for table
    void printTableLine() {
        std::cout << "+" << std::string(timestampWidth + 2, '-')
                  << "+" << std::string(eventTypeWidth + 2, '-')
                  << "+" << std::string(pidWidth + 2, '-')
                  << "+" << std::string(processNameWidth + 2, '-')
                  << "+" << std::string(100, '-') // Fixed width for visual reference
                  << "+" << std::endl;
    }
    
    // Print table header
    void printTableHeader() {
        printTableLine();
        std::cout << "| " << std::left << std::setw(timestampWidth) << "Timestamp"
                  << " | " << std::setw(eventTypeWidth) << "Event Type"
                  << " | " << std::setw(pidWidth) << "PID"
                  << " | " << std::setw(processNameWidth) << "Process Name"
                  << " | " << "Path"  // No fixed width for path column
                  << std::endl;
        printTableLine();
    }

public:
    EventLogger(const std::string& outputPath, bool enableConsoleOutput = true) 
        : outputFilePath(outputPath), consoleOutputEnabled(enableConsoleOutput) {
        // Open output file
        outputFile.open(outputFilePath, std::ios::out | std::ios::trunc);
        if (!outputFile.is_open()) {
            std::cerr << "Failed to open output file: " << outputFilePath << std::endl;
            throw std::runtime_error("Failed to open output file");
        }
        
        // Initialize JSON array for events
        outputFile << "[]" << std::endl;
        outputFile.flush();
        
        // Print table header if console output is enabled
        if (consoleOutputEnabled) {
            std::cout << "File Monitoring Events" << std::endl;
            printTableHeader();
        }
    }
    
    ~EventLogger() {
        if (outputFile.is_open()) {
            outputFile.close();
        }
    }
    
    // Log a file event
    void logEvent(const FileEvent& event) {
        // Lock for thread safety
        std::lock_guard<std::mutex> lock(eventMutex);
        
        // Add event to buffer
        eventBuffer.push_back(event);
        
        // Convert event to JSON
        json eventJson = event.toJson();
        
        // Append to output file
        // Need to seek to position before the closing bracket
        outputFile.seekp(-2, std::ios::end);
        
        // If the file has events already, add a comma
        if (eventBuffer.size() > 1) {
            outputFile << "," << std::endl;
        }
        
        // Write event and close the array
        outputFile << eventJson.dump(2) << std::endl << "]";
        outputFile.flush();
        
        // Print to console if enabled
        if (consoleOutputEnabled) {
            // Format timestamp
            std::string timestamp = formatTimestamp(event.timestamp);
            
            // Get color for event type
            std::string eventColor = getColorForEventType(event.eventType);
            
            // Print table row with fixed width columns except path
            std::cout << "| " << std::left << std::setw(timestampWidth) << timestamp
                      << " | " << eventColor << std::setw(eventTypeWidth) << event.eventType << colorReset
                      << " | " << std::setw(pidWidth) << event.pid
                      << " | " << std::setw(processNameWidth) << truncateString(event.processName, processNameWidth)
                      << " | " << event.path  // No fixed width for path
                      << std::endl;
        }
    }
};

// Inotify Monitor class
class InotifyMonitor {
private:
    int inotifyFd;
    std::map<int, std::string> watchDescriptors;
    std::atomic<bool> running;
    std::thread monitorThread;
    ConfigManager& config;
    ProcessMonitor& processMonitor;
    std::function<void(const FileEvent&)> eventCallback;
    pid_t ownPid;

    // Initialize inotify
    bool initInotify() {
        inotifyFd = inotify_init1(IN_NONBLOCK);
        if (inotifyFd == -1) {
            std::cerr << "Failed to initialize inotify: " << strerror(errno) << std::endl;
            return false;
        }
        return true;
    }

    // Add watch to directory and its subdirectories
    // addWatchRecursive function was modified to ignore symlinks and also warn about inotify's rate limit.

void addWatchRecursive(const std::string& path, int depth = 0) {
    static int watchCount = 0;
    static bool watchLimitReached = false;
    
    // Skip if we've already hit the limit or depth limit
    if (watchLimitReached || depth > 20) {
        return;
    }

    if (config.isPathExcluded(path)) {
        return;
    }

    // Add watch to current directory
    uint32_t mask = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | 
                     IN_CLOSE_WRITE | IN_ATTRIB;
    int wd = inotify_add_watch(inotifyFd, path.c_str(), mask);
    
    if (wd == -1) {
        if (errno == ENOSPC) {
            // Hit the inotify watch limit
            if (!watchLimitReached) {
                watchLimitReached = true;
                std::cerr << "Inotify watch limit reached (" << watchCount << " watches). Not all directories will be monitored." << std::endl;
                std::cerr << "To increase limit: echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p" << std::endl;
            }
            return;
        } else {
            std::cerr << "Failed to add inotify watch for " << path << ": " << strerror(errno) << std::endl;
            return;
        }
    }
    
    watchCount++;
    watchDescriptors[wd] = path;

    try {
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) continue;
            
            bool isDir = false;
            bool isSymlink = false;
            
            try {
                isDir = fs::is_directory(entry.path(), ec);
                isSymlink = fs::is_symlink(entry.path(), ec);
            } catch (...) {
                continue;
            }
            
            if (ec) continue;
            
            if (isDir && !isSymlink && !config.isPathExcluded(entry.path())) {
                addWatchRecursive(entry.path().string(), depth + 1);
                
                // Exit early if we hit the watch limit
                if (watchLimitReached) break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error scanning directory " << path << ": " << e.what() << std::endl;
    }
}

    // Handle inotify events
    void handleEvents() {
        const size_t EVENT_BUF_LEN = 4096;
        char buffer[EVENT_BUF_LEN];
        
        while (running) {
            // Set up select() to wait for events with a timeout
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(inotifyFd, &fds);
            
            // Set timeout to 1 second
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            int ret = select(inotifyFd + 1, &fds, nullptr, nullptr, &timeout);
            
            if (ret == -1) {
                std::cerr << "select() error: " << strerror(errno) << std::endl;
                break;
            } else if (ret == 0) {
                // Timeout, just continue
                continue;
            }
            
            // Read events
            ssize_t len = read(inotifyFd, buffer, EVENT_BUF_LEN);
            if (len == -1 && errno != EAGAIN) {
                std::cerr << "read() error: " << strerror(errno) << std::endl;
                break;
            }
            
            if (len <= 0) {
                continue;
            }
            
            // Process events
            ssize_t i = 0;
            while (i < len) {
                struct inotify_event* event = reinterpret_cast<struct inotify_event*>(&buffer[i]);
                
                // Get the path from watch descriptor
                if (watchDescriptors.find(event->wd) != watchDescriptors.end()) {
                    std::string path = watchDescriptors[event->wd];
                    
                    // Add the filename if present
                    if (event->len > 0) {
                        path += "/" + std::string(event->name);
                    }
                    
                    // Check if path should be excluded
                    if (!config.isPathExcluded(path)) {
                        // Determine event type
                        std::string eventType;
                        if (event->mask & IN_CREATE) {
                            eventType = "CREATE";
                            
                            // Add watch if the created item is a directory
                            if (event->mask & IN_ISDIR) {
                                std::string newDir = watchDescriptors[event->wd] + "/" + event->name;
                                addWatchRecursive(newDir);
                            }
                        } else if (event->mask & IN_MODIFY) {
                            eventType = "MODIFY";
                        } else if (event->mask & IN_DELETE) {
                            eventType = "DELETE";
                        } else if (event->mask & IN_MOVED_FROM) {
                            eventType = "MOVED_FROM";
                        } else if (event->mask & IN_MOVED_TO) {
                            eventType = "MOVED_TO";
                        } else if (event->mask & IN_CLOSE_WRITE) {
                            eventType = "CLOSE_WRITE";
                        } else if (event->mask & IN_ATTRIB) {
                            eventType = "ATTRIB";
                        } else {
                            eventType = "UNKNOWN";
                        }
                        
                        // We don't have process information from inotify
                        // This will be provided by fanotify for file access events
                        FileEvent fileEvent;
                        fileEvent.path = path;
                        fileEvent.eventType = eventType;
                        fileEvent.timestamp = time(nullptr);
                        fileEvent.pid = -1; // Unknown PID
                        fileEvent.processName = "Unknown"; // Unknown process
                        
                        if (eventCallback) {
                            eventCallback(fileEvent);
                        }
                    }
                }
                
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }

public:
    InotifyMonitor(ConfigManager& configManager, ProcessMonitor& procMonitor) 
        : inotifyFd(-1), running(false), config(configManager), processMonitor(procMonitor) {
        ownPid = getpid();
    }
    
    ~InotifyMonitor() {
        stop();
        if (inotifyFd != -1) {
            close(inotifyFd);
        }
    }
    
    // Set callback for event notification
    void setEventCallback(std::function<void(const FileEvent&)> callback) {
        eventCallback = callback;
    }
    
    // Start monitoring
    bool start(const std::string& rootPath = "/") {
        if (!initInotify()) {
            return false;
        }
        
        running = true;
        
        // Add watches recursively starting from root path
        addWatchRecursive(rootPath);
        
        // Start monitoring thread
        monitorThread = std::thread(&InotifyMonitor::handleEvents, this);
        
        return true;
    }
    
    // Stop monitoring
    void stop() {
        running = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
};

// Fanotify Monitor class
class FanotifyMonitor {
private:
    int fanotifyFd;
    std::atomic<bool> running;
    std::thread monitorThread;
    ConfigManager& config;
    ProcessMonitor& processMonitor;
    std::function<void(const FileEvent&)> eventCallback;
    pid_t ownPid;

    // Initialize fanotify
    bool initFanotify() {
        // Initialize fanotify
        fanotifyFd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY);
        if (fanotifyFd == -1) {
            std::cerr << "Failed to initialize fanotify: " << strerror(errno) << std::endl;
            std::cerr << "You may need to run this program with sudo or enable CAP_SYS_ADMIN capability." << std::endl;
            return false;
        }
        return true;
    }

    // Set up monitor points
    bool setupMonitoring(const std::string& rootPath) {
        // Mark the mount point for monitoring
        if (fanotify_mark(fanotifyFd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                          FAN_OPEN | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_ACCESS,
                          AT_FDCWD, rootPath.c_str()) == -1) {
            std::cerr << "Failed to add fanotify watch on " << rootPath << ": " << strerror(errno) << std::endl;
            return false;
        }

        // Exclude specific directories
        for (const auto& excludedPath : config.getExcludedPaths()) {
            if (fs::exists(excludedPath)) {
                if (fanotify_mark(fanotifyFd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                                  FAN_OPEN | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_ACCESS,
                                  AT_FDCWD, excludedPath.c_str()) == -1) {
                    std::cerr << "Failed to exclude " << excludedPath << ": " << strerror(errno) << std::endl;
                }
            }
        }

        return true;
    }

    // Utility function to get path from file descriptor
    std::string getPathFromFd(int fd) {
        char path[PATH_MAX];
        char procPath[PATH_MAX];
        
        snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(procPath, path, sizeof(path) - 1);
        
        if (len == -1) {
            return "Unknown";
        }
        
        path[len] = '\0';
        return std::string(path);
    }

    // Handler thread function
    void handleEvents() {
        const size_t EVENT_BUF_LEN = 4096;
        char buffer[EVENT_BUF_LEN];

        while (running) {
            // Set up select() to wait for events with a timeout
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fanotifyFd, &fds);
            
            // Set timeout to 1 second
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            int ret = select(fanotifyFd + 1, &fds, nullptr, nullptr, &timeout);
            
            if (ret == -1) {
                std::cerr << "select() error: " << strerror(errno) << std::endl;
                break;
            } else if (ret == 0) {
                // Timeout, just continue
                continue;
            }
            
            // Read events
            ssize_t len = read(fanotifyFd, buffer, EVENT_BUF_LEN);
            if (len == -1 && errno != EAGAIN) {
                std::cerr << "read() error: " << strerror(errno) << std::endl;
                break;
            }
            
            if (len <= 0) {
                continue;
            }
            
            // Process events
            struct fanotify_event_metadata* metadata;
            metadata = (struct fanotify_event_metadata*)buffer;
            
            while (FAN_EVENT_OK(metadata, len)) {
                // Skip events from our own process
                if (!config.shouldMonitorOwnEvents() && metadata->pid == ownPid) {
                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }
                
                // Get the file path
                std::string path = getPathFromFd(metadata->fd);
                
                // Close the file descriptor
                close(metadata->fd);
                
                // Skip excluded paths
                if (config.isPathExcluded(path)) {
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }
                
                // Determine the event type
                std::string eventType;
                if (metadata->mask & FAN_OPEN) {
                    eventType = "OPEN";
                } else if (metadata->mask & FAN_CLOSE_WRITE) {
                    eventType = "CLOSE_WRITE";
                } else if (metadata->mask & FAN_CLOSE_NOWRITE) {
                    eventType = "CLOSE_NOWRITE";
                } else if (metadata->mask & FAN_ACCESS) {
                    eventType = "ACCESS";
                } else {
                    eventType = "UNKNOWN";
                }
                
                // Get process name
                std::string processName = processMonitor.getProcessName(metadata->pid);
                
                // Create the file event
                FileEvent fileEvent;
                fileEvent.path = path;
                fileEvent.eventType = eventType;
                fileEvent.timestamp = time(nullptr);
                fileEvent.pid = metadata->pid;
                fileEvent.processName = processName;
                
                // Invoke the callback function
                if (eventCallback) {
                    eventCallback(fileEvent);
                }
                
                // Move to the next event
                metadata = FAN_EVENT_NEXT(metadata, len);
            }
        }
    }

public:
    FanotifyMonitor(ConfigManager& configManager, ProcessMonitor& procMonitor) 
        : fanotifyFd(-1), running(false), config(configManager), processMonitor(procMonitor) {
        ownPid = getpid();
    }
    
    ~FanotifyMonitor() {
        stop();
        if (fanotifyFd != -1) {
            close(fanotifyFd);
        }
    }
    
    // Set callback for event notification
    void setEventCallback(std::function<void(const FileEvent&)> callback) {
        eventCallback = callback;
    }
    
    // Start monitoring
    bool start(const std::string& rootPath = "/") {
        if (!initFanotify()) {
            return false;
        }
        
        if (!setupMonitoring(rootPath)) {
            close(fanotifyFd);
            fanotifyFd = -1;
            return false;
        }
        
        running = true;
        monitorThread = std::thread(&FanotifyMonitor::handleEvents, this);
        
        return true;
    }
    
    // Stop monitoring
    void stop() {
        running = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
};

// Combined file monitoring system
class FileMonitoringSystem {
private:
    ConfigManager config;
    ProcessMonitor processMonitor;
    std::unique_ptr<EventLogger> logger;
    std::unique_ptr<InotifyMonitor> inotifyMonitor;
    std::unique_ptr<FanotifyMonitor> fanotifyMonitor;
    std::string monitoredPath;
    std::atomic<bool> running;
    std::string actualOutputFile;

    // Generate a timestamped output file name
    std::string generateTimestampedFileName(const std::string& baseFileName) {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now = *std::localtime(&time_t_now);
        
        // Format: baseFileName_YYYY-MM-DD_HHMMSS.json
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "_%Y-%m-%d_%H%M%S", &tm_now);
        
        std::string timestampedName = baseFileName;
        // Remove .json extension if present
        size_t jsonPos = timestampedName.rfind(".json");
        if (jsonPos != std::string::npos) {
            timestampedName = timestampedName.substr(0, jsonPos);
        }
        
        timestampedName += std::string(buffer) + ".json";
        return timestampedName;
    }

    // Event callback function
    void onFileEvent(const FileEvent& event) {
        if (logger) {
            // Extra filtering for log files
            if (event.path.find(actualOutputFile) != std::string::npos) {
                return; // Skip events related to our own log file
            }
            
            logger->logEvent(event);
        }
    }

public:// modified to accept custom config path
    FileMonitoringSystem(const std::string& configPath = "config.json") 
    : config(configPath), running(false) {
    
    // Generate timestamped output file name
    actualOutputFile = generateTimestampedFileName(config.getOutputFile());
    } 
    
    ~FileMonitoringSystem() {
        stop();
    }
    
    // Start monitoring
    bool start(const std::string& path = "/") {
        monitoredPath = path;
        running = true;
        
        // ANSI color codes
        const std::string colorRed = "\033[31m";
        const std::string colorBrightRed = "\033[91m";
        const std::string colorReset = "\033[0m";
        
        // Display ASCII art and program name
        std::cout << colorBrightRed << 
        "               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@+===========+@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@====-------------====@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@==---------@@@@@@------==@@@@@@@@@@@@\n"
        "               @@@@@@@@@==----------@@@@@----------==@@@@@@@@@@\n"
        "               @@@@@@@#=-----------@@@@@@@-----------=+@@@@@@@@\n"
        "               @@@@@@==---------+=--@@@@@--=+---------==@@@@@@@\n"
        "               @@@@@@=--------+---------------+--------=*@@@@@@\n"
        "               @@@@@=--------+----=========----+=-------=@@@@@@\n"
        "               @@@@+=-------+---===+@@@@@+===---+-------==@@@@@\n"
        "               @@@@==------==---==+@@@@@@@+===---+------==@@@@@\n"
        "               @@@@==------=---==+@@@@@@@@@+==---+------==@@@@@\n"
        "               @@@@==------=++--==+@@@@@@@+==--@@=------==@@@@@\n"
        "               @@@@@=--@---@@@@@-===+@@@@+==-@@@@@@-----=%@@@@@\n"
        "               @@@@@=---@@@@@@@@---=======---@@@@@@@---==@@@@@@\n"
        "               @@@@@@==-_@@@@@@#-------------+@@@@@@---=@@@@@@@\n"
        "               @@@@@@@==---------+---------+-----@@---=@@@@@@@@\n"
        "               @@@@@@@@==---------+--+-+-+-----@@@--==@@@@@@@@@\n"
        "               @@@@@@@@@@==-----------------------==#@@@@@@@@@@\n"
        "               @@@@@@@@@@@@==-------------------==@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@#====---------====*@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@@@@=======@@@@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" << colorReset << "\n";
        
        std::cout << colorRed << 
        "░█▀▀░█░█░█▀█░█▀▄░▀█▀░█▀█░█▀▀░█▀█░█▀█░░░░░█▀▀░▀█▀░█░░░█▀▀░░░░░█▄█░█▀█░█▀█░▀█▀░▀█▀░█▀█░█▀▄\n"
        "░▀▀█░█▀█░█▀█░█▀▄░░█░░█░█░█░█░█▀█░█░█░▄▄▄░█▀▀░░█░░█░░░█▀▀░▄▄▄░█░█░█░█░█░█░░█░░░█░░█░█░█▀▄\n"
        "░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀░▀░░░░░▀░░░▀▀▀░▀▀▀░▀▀▀░░░░░▀░▀░▀▀▀░▀░▀░▀▀▀░░▀░░▀▀▀░▀░▀\n" << colorReset << "\n";
        
        std::cout << "Created by Samora Tandon\n"
       "twitter--@tandon_samora   linkedln--Tandon Samora \n\n"
        ;
        
        std::cout << "Starting Sharingan File Monitor...\n" << std::endl;
        
        // Start inotify monitor
        inotifyMonitor = std::make_unique<InotifyMonitor>(config, processMonitor);
        if (!inotifyMonitor->start(path)) {
            std::cerr << "Failed to start inotify monitor" << std::endl;
            return false;
        }
        
        // Start fanotify monitor 
        fanotifyMonitor = std::make_unique<FanotifyMonitor>(config, processMonitor);
        if (!fanotifyMonitor->start(path)) {
            std::cerr << "Failed to start fanotify monitor (may need root privileges)" << std::endl;
            inotifyMonitor->stop();
            return false;
        }
        
        std::cout << "Sharingan File Monitor started. Monitoring path: " << path << std::endl;
        std::cout << "Events are being logged to: " << actualOutputFile << std::endl;
        std::cout << "Monitoring " << path << " directory." << std::endl;
        std::cout << "Press Ctrl+C to stop..." << std::endl;
        
        // Create logger AFTER printing the startup messages
        logger = std::make_unique<EventLogger>(actualOutputFile);
        
        // Set callbacks
        inotifyMonitor->setEventCallback([this](const FileEvent& event) { onFileEvent(event); });
        fanotifyMonitor->setEventCallback([this](const FileEvent& event) { onFileEvent(event); });
        
        return true;
    }
    
    // Stop monitoring
    void stop() {
        if (!running) return;
        
        running = false;
        std::cout << "Stopping Sharingan File Monitor..." << std::endl;
        
        if (inotifyMonitor) inotifyMonitor->stop();
        if (fanotifyMonitor) fanotifyMonitor->stop();
        
        std::cout << "Sharingan File Monitor stopped." << std::endl;
    }

    // Get the monitored path
    std::string getMonitoredPath() const {
        return monitoredPath;
    }
};

// Signal handler for clean termination
std::atomic<bool> g_running(true);
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}

// Main function modified with commmadline arguments
// Main function
int main(int argc, char** argv) {
    // Register signal handler
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Default monitoring path
    std::string monitorPath = "/home";
    // Default config path
    std::string configPath = "config.json";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            // Show help
            std::cout << "Sharingan File Monitor - Linux file activity monitoring tool\n\n"
                      << "Usage: sharingan_file_monitor [OPTIONS]\n\n"
                      << "Options:\n"
                      << "  -p, --path PATH       Path to monitor (default: /home)\n"
                      << "  -c, --config PATH     Path to config file (default: config.json)\n"
                      << "  -h, --help            Show this help message\n\n"
                      << "Examples:\n"
                      << "  sharingan_file_monitor -p /home/user -c custom_config.json\n"
                      << "  sharingan_file_monitor -p /etc\n\n"
                      << "Note: Monitoring root directory (/) is not recommended as it may exceed\n"
                      << "      the system's inotify watch limit. If needed, consider increasing\n"
                      << "      the limit by running:\n"
                      << "      echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p\n";
            return 0;
        } else if (arg == "-p" || arg == "--path") {
            if (i + 1 < argc) {
                monitorPath = argv[++i];
            } else {
                std::cerr << "Error: -p/--path requires a directory argument\n";
                return 1;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                configPath = argv[++i];
            } else {
                std::cerr << "Error: -c/--config requires a file argument\n";
                return 1;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            std::cerr << "Use -h or --help for usage information\n";
            return 1;
        }
    }
    
    // Warn user if monitoring root directory
    if (monitorPath == "/") {
        std::cout << "\n[WARNING] You're attempting to monitor the entire filesystem (/)\n"
                  << "This will likely exceed the system's inotify watch limit.\n"
                  << "Consider monitoring a more specific directory instead.\n"
                  << "To proceed anyway, press Enter. To exit, press Ctrl+C...\n";
        
        std::cin.ignore();
    }
    
    try {
        // Create monitoring system with specified config
        FileMonitoringSystem monitorSystem(configPath);
        
        // Start monitoring
        if (!monitorSystem.start(monitorPath)) {
            std::cerr << "Failed to start Sharingan File Monitor. Exiting." << std::endl;
            return 1;
        }
        
        // Keep running until signal is received
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Clean shutdown
        monitorSystem.stop();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}