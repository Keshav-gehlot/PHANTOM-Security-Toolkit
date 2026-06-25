// main.cpp — PHANTOM Security Toolkit entry point
#include "phantom/core.h"
#include "phantom/ui.h"
#include <string>

int main(int argc, char* argv[]) {
    phantom::init();

    bool use_cli = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--cli") {
            use_cli = true;
            break;
        }
    }

    if (use_cli) {
        phantom::ui::init_menu(); // Enable ANSI on Windows console
        phantom::run();           // Full interactive menu loop
    } else {
        phantom::ui::run_gui_dashboard(); // Launch modern native Win32 GUI Dashboard
    }

    phantom::cleanup();
    return 0;
}
