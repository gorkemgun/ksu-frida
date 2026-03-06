#include "inject.h"

#include <unistd.h>

#include <chrono>
#include <cinttypes>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "config.h"
#include "log.h"
#include "child_gating.h"
#include "xdl.h"
#include "anti_detect.h"

static std::string get_process_name() {
    std::ifstream file("/proc/self/cmdline");
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

static void wait_for_init(std::string const &app_name) {
    LOGI("Wait for process to complete init");

    while (get_process_name().find(app_name) == std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Additional tolerance for the init to complete after process rename.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOGI("Process init completed");
}

static void delay_start_up(uint64_t start_up_delay_ms) {
    if (start_up_delay_ms <= 0) {
        return;
    }

    LOGI("Waiting for configured start up delay %" PRIu64 "ms", start_up_delay_ms);

    int countdown = 0;
    uint64_t delay = start_up_delay_ms;

    for (int i = 0; i < 10 && delay > 1000; i++) {
        delay -= 1000;
        countdown++;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    for (int i = countdown; i > 0; i--) {
        LOGI("Injecting libs in %d seconds", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void inject_lib(std::string const &lib_path, std::string const &logContext) {
    // Try xdl_open first; it can bypass certain linker restrictions.
    void *handle = xdl_open(lib_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("%sInjected %s with handle %p", logContext.c_str(), lib_path.c_str(), handle);
        return;
    }

    auto xdl_err = dlerror();

    // Fall back to standard dlopen.
    handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (handle) {
        LOGI("%sInjected %s with handle %p (dlopen fallback)",
             logContext.c_str(), lib_path.c_str(), handle);
        return;
    }

    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s",   logContext.c_str(), lib_path.c_str(), dlerror());
}

static void inject_libs(target_config const &cfg) {
    wait_for_init(cfg.app_name);
    install_anti_detect_hooks();

    if (cfg.child_gating.enabled) {
        enable_child_gating(cfg.child_gating);
    }

    delay_start_up(cfg.start_up_delay_ms);

    for (auto &lib_path : cfg.injected_libraries) {
        LOGI("Injecting %s", lib_path.c_str());
        inject_lib(lib_path, "");
    }

    // Allow Frida's JS engine to fully initialize before post-init cleanup.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    remap_hooked_system_libs();
}

bool check_and_inject(std::string const &app_name) {
    std::string module_dir = std::string("/data/local/tmp/libsec");

    std::optional<target_config> cfg = load_config(module_dir, app_name);
    if (!cfg.has_value()) {
        return false;
    }

    LOGI("App detected: %s", app_name.c_str());
    LOGI("PID: %d", getpid());

    auto target_config = cfg.value();
    if (!target_config.enabled) {
        LOGI("Injection disabled for %s", app_name.c_str());
        return false;
    }

    std::thread inject_thread(inject_libs, target_config);
    inject_thread.detach();

    return true;
}
