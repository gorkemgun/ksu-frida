#include "inject.h"

#include <cstddef>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <chrono>
#include <cinttypes>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "config.h"
#include "log.h"
#include "child_gating.h"
#include "xdl.h"
#include "remapper.h"

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

static bool copy_file(const char *src, const char *dst) {
    int in_fd = open(src, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        LOGE("stage: open src failed: %s", src);
        return false;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (out_fd < 0) {
        LOGE("stage: open dst failed: %s", dst);
        close(in_fd);
        return false;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write(out_fd, buf, (size_t)n) != n) {
            LOGE("stage: write failed for %s", dst);
            close(in_fd);
            close(out_fd);
            return false;
        }
    }

    close(in_fd);
    close(out_fd);
    return true;
}

static std::string stage_gadget(const std::string &app_name, const std::string &src_lib_path) {

    std::string stage_dir = "/data/data/" + app_name + "/.cache";
    mkdir(stage_dir.c_str(), 0700);

    size_t slash = src_lib_path.rfind('/');
    std::string lib_name = (slash == std::string::npos) ? src_lib_path : src_lib_path.substr(slash + 1);
    std::string cfg_name = lib_name;
    size_t dot = cfg_name.rfind(".so");
    if (dot != std::string::npos) cfg_name.insert(dot, ".config");

    std::string src_dir = (slash == std::string::npos) ? "." : src_lib_path.substr(0, slash);
    std::string src_cfg  = src_dir + "/" + cfg_name;
    std::string dst_lib  = stage_dir + "/" + lib_name;
    std::string dst_cfg  = stage_dir + "/" + cfg_name;

    LOGI("Staging gadget: %s -> %s", src_lib_path.c_str(), dst_lib.c_str());

    if (!copy_file(src_lib_path.c_str(), dst_lib.c_str())) {
        return "";
    }

    copy_file(src_cfg.c_str(), dst_cfg.c_str());
    return dst_lib;
}

static void unlink_staged(const std::string &staged_lib_path) {
    unlink(staged_lib_path.c_str());

    std::string cfg = staged_lib_path;
    size_t dot = cfg.rfind(".so");
    if (dot != std::string::npos) cfg.insert(dot, ".config");
    unlink(cfg.c_str());

    size_t slash = staged_lib_path.rfind('/');
    if (slash != std::string::npos) {
        rmdir(staged_lib_path.substr(0, slash).c_str());
    }

    LOGI("Staged files removed");
}

// ── Injection ─────────────────────────────────────────────────────────────────
void inject_lib(std::string const &lib_path, std::string const &logContext) {
    void *handle = xdl_open(lib_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("%sInjected %s with handle %p", logContext.c_str(), lib_path.c_str(), handle);
        return;
    }

    auto xdl_err = dlerror();
    // Fall back to standard dlopen.
    handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (handle) {
        LOGI("%sInjected %s with handle %p (dlopen fallback)", logContext.c_str(), lib_path.c_str(), handle);
        remap_lib(lib_path);
        return;
    }

    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s",   logContext.c_str(), lib_path.c_str(), dlerror());
}

static void inject_libs(target_config const &cfg, pid_t pid) {
    wait_for_init(cfg.app_name);

    if (cfg.child_gating.enabled) {
        enable_child_gating(cfg.child_gating);
    }

    if (cfg.kernel_assisted_evasion) {
        LOGI("KSIE enabled for PID: %d", pid);
    }

    delay_start_up(cfg.start_up_delay_ms);

    for (auto const &lib_path : cfg.injected_libraries) {
        std::string staged = stage_gadget(cfg.app_name, lib_path);
        std::string inject_path = staged.empty() ? lib_path : staged;

        LOGI("Injecting %s", inject_path.c_str());
        inject_lib(inject_path, "");

        if (!staged.empty()) {
            unlink_staged(staged);
        }
    }

    // Allow Frida's JS engine to fully initialize before post-init cleanup.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

bool check_and_inject(std::string const &app_name) {
    std::string module_dir = std::string("/data/local/tmp/libsec");

    std::optional<target_config> cfg = load_config(module_dir, app_name);
    if (!cfg.has_value()) {
        return false;
    }

    pid_t pid = getpid();

    LOGI("App detected: %s", app_name.c_str());
    LOGI("PID: %d", pid);

    auto target_config = cfg.value();
    if (!target_config.enabled) {
        LOGI("Injection disabled for %s", app_name.c_str());
        return false;
    }

    std::thread inject_thread(inject_libs, target_config, pid);
    inject_thread.detach();

    return true;
}
