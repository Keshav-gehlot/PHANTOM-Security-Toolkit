// utils.cpp — PHANTOM core utilities
#include "phantom/core.h"
#include <iostream>

namespace phantom {
    void init() {
        // Core init — ANSI and console setup handled by menu
    }

    // run() is defined in src/ui/menu.cpp to avoid linking to ncurses
    // and to keep the dispatcher co-located with the menu renderer.

    void cleanup() {
        // Core cleanup
    }
}
