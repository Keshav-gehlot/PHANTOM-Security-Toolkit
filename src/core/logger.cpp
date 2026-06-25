#include "phantom/utils.h"
#include <iostream>

namespace phantom::utils {
    void log_info(const std::string& msg) {
        std::cout << "[INFO] " << msg << std::endl;
    }
    
    void log_error(const std::string& msg) {
        std::cerr << "[ERROR] " << msg << std::endl;
    }
}
