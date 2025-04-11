#include "finaldefi/sdk/FinalDefiSDK.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include "finaldefi/secure_gateway/SecureGateway.hpp"
#include "finaldefi/secure_gateway/HTTPServer.hpp"
#include "finaldefi/secure_gateway/AuditLayer.hpp"
#include "finaldefi/secure_gateway/NodeRegistrySecure.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstring>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <condition_variable>

using namespace finaldefi::sdk;
using namespace finaldefi::secure_gateway;

// Global variables for signal handling
std::atomic<bool> running(true);
std::mutex shutdown_mutex;
std::condition_variable shutdown_cv;

// Components
std::unique_ptr<SecureGateway> gateway;
std::unique_ptr<HTTPServer> http_server;
std::unique_ptr<AuditLayer> audit_layer;

// Version information
const std::string VERSION = "0.2.0";
const std::string BUILD_DATE = __DATE__ " " __TIME__;

// Configuration
struct CommandLineOptions {
    std::string config_file;
    std::string http_bind;
    uint16_t http_port = 8443;
    std::string node_manager_address;
    uint16_t node_manager_port = 9443;
    std::string finalchain_url = "finalchain.final-de.fi";
    std::string log_level = "info";
    bool daemon = false;
    bool version = false;
    bool help = false;
};

// Signal handler
void signal_handler(int sig) {
    SecureLogger::instance().info("Received signal " + std::to_string(sig) + ", initiating graceful shutdown");
    running = false;
    shutdown_cv.notify_all();
}

// Set up security features
void setup_security() {
    // Set resource limits to prevent core dumps
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        SecureLogger::instance().warning("Failed to disable core dumps: " + std::string(strerror(errno)));
    }
    
    // Lock memory to prevent sensitive data from being swapped
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        SecureLogger::instance().warning("Failed to lock memory pages: " + std::string(strerror(errno)));
    } else {
        SecureLogger::instance().info("Memory pages locked successfully");
    }
    
    // Set secure permissions on /dev/shm (shared memory)
    chmod("/dev/shm", 0700);
}

// Parse command line arguments
CommandLineOptions parse_args(int argc, char* argv[]) {
    CommandLineOptions options;
    
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"http-bind", required_argument, 0, 'b'},
        {"http-port", required_argument, 0, 'p'},
        {"node-manager", required_argument, 0, 'n'},
        {"node-manager-port", required_argument, 0, 'm'},
        {"finalchain-url", required_argument, 0, 'f'},
        {"log-level", required_argument, 0, 'l'},
        {"daemon", no_argument, 0, 'd'},
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "c:b:p:n:m:f:l:dvh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                options.config_file = optarg;
                break;
            case 'b':
                options.http_bind = optarg;
                break;
            case 'p':
                options.http_port = static_cast<uint16_t>(std::stoi(optarg));
                break;
            case 'n':
                options.node_manager_address = optarg;
                break;
            case 'm':
                options.node_manager_port = static_cast<uint16_t>(std::stoi(optarg));
                break;
            case 'f':
                options.finalchain_url = optarg;
                break;
            case 'l':
                options.log_level = optarg;
                break;
            case 'd':
                options.daemon = true;
                break;
            case 'v':
                options.version = true;
                break;
            case 'h':
                options.help = true;
                break;
            default:
                break;
        }
    }
    
    return options;
}

// Load configuration from file
void load_config(CommandLineOptions& options) {
    if (options.config_file.empty()) {
        // Look for default config locations
        std::vector<std::string> config_paths = {
            "/etc/finaldefi/secure_gateway.conf",
            "./secure_gateway.conf",
            "../config/secure_gateway.conf",
        };
        
        for (const auto& path : config_paths) {
            if (std::filesystem::exists(path)) {
                options.config_file = path;
                break;
            }
        }
    }
    
    if (!options.config_file.empty() && std::filesystem::exists(options.config_file)) {
        std::ifstream config_file(options.config_file);
        std::string line;
        
        while (std::getline(config_file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }
            
            auto pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                
                // Trim whitespace
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                if (key == "http_bind" && options.http_bind.empty()) {
                    options.http_bind = value;
                } else if (key == "http_port" && value.find_first_not_of("0123456789") == std::string::npos) {
                    options.http_port = static_cast<uint16_t>(std::stoi(value));
                } else if (key == "node_manager_address" && options.node_manager_address.empty()) {
                    options.node_manager_address = value;
                } else if (key == "node_manager_port" && value.find_first_not_of("0123456789") == std::string::npos) {
                    options.node_manager_port = static_cast<uint16_t>(std::stoi(value));
                } else if (key == "finalchain_url" && options.finalchain_url.empty()) {
                    options.finalchain_url = value;
                } else if (key == "log_level" && options.log_level.empty()) {
                    options.log_level = value;
                } else if (key == "daemon" && value == "true") {
                    options.daemon = true;
                }
            }
        }
    }
    
    // Set default values for anything not specified
    if (options.http_bind.empty()) {
        options.http_bind = "0.0.0.0";
    }
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "FinalDeFi Secure Gateway " << VERSION << " (" << BUILD_DATE << ")" << std::endl;
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config=FILE       Configuration file path" << std::endl;
    std::cout << "  -b, --http-bind=ADDR    HTTP server bind address (default: 0.0.0.0)" << std::endl;
    std::cout << "  -p, --http-port=PORT    HTTP server port (default: 8443)" << std::endl;
    std::cout << "  -n, --node-manager=ADDR Node manager address" << std::endl;
    std::cout << "  -m, --node-manager-port=PORT Node manager port (default: 9443)" << std::endl;
    std::cout << "  -f, --finalchain-url=URL FinalChain URL (default: finalchain.final-de.fi)" << std::endl;
    std::cout << "  -l, --log-level=LEVEL   Log level (trace, debug, info, warning, error, critical)" << std::endl;
    std::cout << "  -d, --daemon            Run as daemon" << std::endl;
    std::cout << "  -v, --version           Print version information and exit" << std::endl;
    std::cout << "  -h, --help              Print this help message and exit" << std::endl;
}

// Print version information
void print_version() {
    std::cout << "FinalDeFi Secure Gateway " << VERSION << " (" << BUILD_DATE << ")" << std::endl;
    std::cout << "Copyright (c) 2023-2025 FinalDeFi" << std::endl;
    std::cout << "Post-Quantum Secure Gateway for Cross-Chain DeFi" << std::endl;
}

// Daemonize the process
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) {
        // Parent process exits
        exit(EXIT_SUCCESS);
    }
    
    // Child process continues
    umask(0);
    
    // Create a new session and process group
    pid_t sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Change working directory to root
    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect standard file descriptors to /dev/null
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

// Set up directories
void setup_directories() {
    std::vector<std::string> dirs = {
        constants::LOG_PATH,
        constants::TRANSACTION_STORE_PATH,
        constants::ATTESTATION_STORE_PATH,
        std::filesystem::path(constants::SECRET_FILE_PATH).parent_path().string(),
        std::filesystem::path(constants::REGISTRY_FILE_PATH).parent_path().string()
    };
    
    for (const auto& dir : dirs) {
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }
    }
}

// Initialize SecureLogger
void init_logger(const std::string& log_level) {
    SecureLogger::LogLevel level = SecureLogger::LogLevel::INFO;
    
    if (log_level == "trace") {
        level = SecureLogger::LogLevel::TRACE;
    } else if (log_level == "debug") {
        level = SecureLogger::LogLevel::DEBUG;
    } else if (log_level == "info") {
        level = SecureLogger::LogLevel::INFO;
    } else if (log_level == "warning") {
        level = SecureLogger::LogLevel::WARNING;
    } else if (log_level == "error") {
        level = SecureLogger::LogLevel::ERROR;
    } else if (log_level == "critical") {
        level = SecureLogger::LogLevel::CRITICAL;
    }
    
    SecureLogger::instance().initialize(constants::LOG_PATH, level);
}

// Create a gateway node ID
std::array<uint8_t, constants::NODE_ID_SIZE> create_node_id() {
    std::array<uint8_t, constants::NODE_ID_SIZE> node_id;
    
    // Check if node ID file exists
    std::string node_id_file = "/var/lib/finaldefi/node_id";
    
    if (std::filesystem::exists(node_id_file)) {
        // Load existing node ID
        std::ifstream file(node_id_file, std::ios::binary);
        file.read(reinterpret_cast<char*>(node_id.data()), node_id.size());
    } else {
        // Generate a new node ID
        randombytes_buf(node_id.data(), node_id.size());
        
        // Save the node ID
        std::filesystem::create_directories(std::filesystem::path(node_id_file).parent_path());
        std::ofstream file(node_id_file, std::ios::binary);
        file.write(reinterpret_cast<const char*>(node_id.data()), node_id.size());
    }
    
    return node_id;
}

// Configure and build the Gateway
GatewayConfig build_gateway_config(const CommandLineOptions& options) {
    GatewayConfig config;
    
    // HTTP server configuration
    config.http_bind_address = options.http_bind;
    config.http_bind_port = options.http_port;
    
    // WebSocket server configuration
    config.ws_bind_address = options.http_bind;
    config.ws_bind_port = options.http_port + 1;
    
    // Node manager configuration
    config.node_manager_address = options.node_manager_address;
    config.node_manager_port = options.node_manager_port;
    
    // FinalChain configuration
    config.finalchain_url = options.finalchain_url;
    
    // Gateway identification
    config.node_name = "SecureGateway-" + FinalDefiSDK::generate_uuid();
    config.node_id = create_node_id();
    
    // Quorum parameters
    config.quorum_threshold = constants::QUORUM_THRESHOLD;
    config.quorum_total = constants::QUORUM_TOTAL;
    
    // Thread pool configuration
    config.thread_pool_size = std::thread::hardware_concurrency() * 2;
    
    // Transaction processing configuration
    config.max_concurrent_tx = config.thread_pool_size * 4;
    config.transaction_buffer_size = constants::TRANSACTION_BUFFER_SIZE;
    
    // Epoch configuration
    config.epoch_interval = constants::EPOCH_INTERVAL;
    
    // Storage paths
    config.transaction_store_path = constants::TRANSACTION_STORE_PATH;
    config.attestation_store_path = constants::ATTESTATION_STORE_PATH;
    config.log_path = constants::LOG_PATH;
    
    // Key rotation interval
    config.key_rotation_interval = constants::KEY_ROTATION_INTERVAL;
    
    return config;
}

// Initialize all components
bool initialize_components(const GatewayConfig& config) {
    try {
        // Initialize SDK
        auto sdk_result = FinalDefiSDK::initialize();
        if (sdk_result.is_err()) {
            SecureLogger::instance().critical("Failed to initialize FinalDefiSDK: " + 
                                     sdk_result.error_message());
            return false;
        }
        
        // Initialize SecureGateway
        gateway = std::make_unique<SecureGateway>(config);
        auto gateway_init_result = gateway->initialize();
        if (gateway_init_result.is_err()) {
            SecureLogger::instance().critical("Failed to initialize SecureGateway: " + 
                                     gateway_init_result.error_message());
            return false;
        }
        
        // Start the gateway
        auto gateway_start_result = gateway->start();
        if (gateway_start_result.is_err()) {
            SecureLogger::instance().critical("Failed to start SecureGateway: " + 
                                     gateway_start_result.error_message());
            return false;
        }
        
        // Initialize HTTP server
        http_server = std::make_unique<HTTPServer>(
            config.http_bind_address, 
            config.http_bind_port, 
            gateway.get()
        );
        
        // Start HTTP server
        http_server->start();
        
        SecureLogger::instance().info("FinalDeFi Secure Gateway initialized successfully");
        return true;
    } catch (const std::exception& e) {
        SecureLogger::instance().critical("Exception during component initialization: " + 
                                 std::string(e.what()));
        return false;
    }
}

// Shutdown all components
void shutdown_components() {
    try {
        SecureLogger::instance().info("Shutting down components...");
        
        // Stop HTTP server
        if (http_server) {
            http_server->stop();
            http_server.reset();
        }
        
        // Stop gateway
        if (gateway) {
            gateway->stop();
            gateway.reset();
        }
        
        // Shutdown SDK
        FinalDefiSDK::shutdown();
        
        SecureLogger::instance().info("All components shut down successfully");
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during component shutdown: " + 
                               std::string(e.what()));
    }
}

// Main entry point
int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments
        CommandLineOptions options = parse_args(argc, argv);
        
        // Handle version and help flags
        if (options.version) {
            print_version();
            return EXIT_SUCCESS;
        }
        
        if (options.help) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        
        // Load configuration from file
        load_config(options);
        
        // Setup directories
        setup_directories();
        
        // Initialize logger
        init_logger(options.log_level);
        
        // Log startup information
        SecureLogger::instance().info("FinalDeFi Secure Gateway " + VERSION + " starting...");
        
        // Run as daemon if requested
        if (options.daemon) {
            SecureLogger::instance().info("Running as daemon");
            daemonize();
        }
        
        // Set up security features
        setup_security();
        
        // Set up signal handlers
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGQUIT, signal_handler);
        
        // Build gateway configuration
        GatewayConfig gateway_config = build_gateway_config(options);
        
        // Initialize all components
        if (!initialize_components(gateway_config)) {
            SecureLogger::instance().critical("Failed to initialize components");
            return EXIT_FAILURE;
        }
        
        // Wait for shutdown signal
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex);
            SecureLogger::instance().info("FinalDeFi Secure Gateway " + VERSION + 
                                 " started successfully, serving requests on " + 
                                 options.http_bind + ":" + std::to_string(options.http_port));
            
            shutdown_cv.wait(lock, [] { return !running; });
        }
        
        // Shutdown all components
        shutdown_components();
        
        SecureLogger::instance().info("FinalDeFi Secure Gateway " + VERSION + " shutdown complete");
        return EXIT_SUCCESS;
        
    } catch (const std::exception& e) {
        if (SecureLogger::is_initialized()) {
            SecureLogger::instance().critical("Fatal exception: " + std::string(e.what()));
        } else {
            std::cerr << "Fatal exception: " << e.what() << std::endl;
        }
        
        return EXIT_FAILURE;
    }
}