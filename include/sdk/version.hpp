#pragma once

namespace finaldefi {

struct Version {
    static constexpr int major = @PROJECT_VERSION_MAJOR@;
    static constexpr int minor = @PROJECT_VERSION_MINOR@;
    static constexpr int patch = @PROJECT_VERSION_PATCH@;
    static constexpr const char* str = "@PROJECT_VERSION@";
    static constexpr const char* full = "@PROJECT_VERSION@";
    static constexpr const char* name = "FinalDeFi Secure Gateway";
};

} // namespace finaldefi