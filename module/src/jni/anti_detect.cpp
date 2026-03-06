#include "anti_detect.h"

#include <dobby.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <cstdio>

#include "log.h"

// ─────────────────────────────────────────────────────────────────────────────
// Thread-name fingerprints
// ─────────────────────────────────────────────────────────────────────────────

static const char* const FRIDA_THREAD_NAMES[] = {
    "gum-js-loop", "gmain", "gdbus", "gum-dbus", "pool-frida", "linjector", nullptr,
};

static const char* const BENIGN_NAMES[] = {
    "pool-1-thread-1", "pool-2-thread-1", "pool-1-thread-2", "pool-3-thread-1",
    "pool-2-thread-2", "pool-4-thread-1", "pool-1-thread-3", "pool-5-thread-1",
};

static const char* const FRIDA_PIPE_ARTIFACTS[] = {
    "linjector", "frida-pipe", "frida-", nullptr,
};

static constexpr int BENIGN_COUNT = 8;
static std::atomic<int> g_name_counter{0};  // NOLINT

static const char* next_benign_name() {
    return BENIGN_NAMES[g_name_counter.fetch_add(1, std::memory_order_relaxed) % BENIGN_COUNT];
}

static bool is_frida_thread_name(const char* name) {
    if (!name) return false;
    for (int i = 0; FRIDA_THREAD_NAMES[i]; i++) {
        if (strstr(name, FRIDA_THREAD_NAMES[i])) return true;
    }
    return false;
}

static bool has_frida_pipe_artifact(const char* buf, ssize_t len) {
    if (!buf || len <= 0) return false;
    for (int i = 0; FRIDA_PIPE_ARTIFACTS[i]; i++) {
        size_t alen = strlen(FRIDA_PIPE_ARTIFACTS[i]);
        if (memmem(buf, (size_t)len, FRIDA_PIPE_ARTIFACTS[i], alen)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook 1: pthread_setname_np — spoof Frida thread names
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*pthread_setname_np_fn)(pthread_t, const char*);
static pthread_setname_np_fn orig_pthread_setname_np = nullptr;  // NOLINT

static int hooked_pthread_setname_np(pthread_t thread, const char* name) {
    if (is_frida_thread_name(name)) {
        const char* rep = next_benign_name();
        LOGI("[anti_detect] pthread_setname_np: '%s' -> '%s'", name, rep);
        return orig_pthread_setname_np(thread, rep);
    }
    return orig_pthread_setname_np(thread, name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook 2: prctl — intercept PR_SET_NAME for Frida threads
// ─────────────────────────────────────────────────────────────────────────────

typedef int (*prctl_fn)(int, unsigned long, unsigned long, unsigned long, unsigned long);
static prctl_fn orig_prctl = nullptr;  // NOLINT

static int hooked_prctl(int option,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5) {
    if (option == PR_SET_NAME) {
        const char* name = reinterpret_cast<const char*>(arg2);
        if (is_frida_thread_name(name)) {
            const char* rep = next_benign_name();
            LOGI("[anti_detect] prctl PR_SET_NAME: '%s' -> '%s'", name, rep);
            return orig_prctl(PR_SET_NAME,
                              reinterpret_cast<unsigned long>(rep),
                              arg3, arg4, arg5);
        }
    }
    return orig_prctl(option, arg2, arg3, arg4, arg5);
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook 4: readlinkat — hide Frida named pipe artifacts
// ─────────────────────────────────────────────────────────────────────────────

typedef ssize_t (*readlinkat_fn)(int, const char*, char*, size_t);
static readlinkat_fn orig_readlinkat = nullptr;  // NOLINT

static ssize_t hooked_readlinkat(int dirfd, const char* pathname,
                                  char* buf, size_t bufsiz) {
    ssize_t ret = orig_readlinkat(dirfd, pathname, buf, bufsiz);
    if (ret > 0 && has_frida_pipe_artifact(buf, ret)) {
        LOGI("[anti_detect] readlinkat: hiding Frida pipe %.*s", (int)ret, buf);
        static const char BENIGN[] = "/dev/null";
        ssize_t blen = (ssize_t)(sizeof(BENIGN) - 1);
        memcpy(buf, BENIGN, (size_t)blen);
        return blen;
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook 5: dl_iterate_phdr — hide injected libraries from enumeration
// ─────────────────────────────────────────────────────────────────────────────

static const char* const DLI_HIDE_NAMES[] = {
    "libcalc", "frida", "gum-js", nullptr,
};

static bool should_hide_lib(const char* name) {
    if (!name || name[0] == '\0') return false;
    for (int i = 0; DLI_HIDE_NAMES[i]; i++) {
        if (strstr(name, DLI_HIDE_NAMES[i])) return true;
    }
    return false;
}

struct dl_iter_wrap {
    int (*orig_cb)(struct dl_phdr_info*, size_t, void*);
    void* orig_data;
};

static int filtered_dl_cb(struct dl_phdr_info* info, size_t size, void* data) {
    auto* wrap = static_cast<dl_iter_wrap*>(data);
    if (should_hide_lib(info->dlpi_name)) {
        LOGI("[anti_detect] dl_iterate_phdr: hiding '%s'", info->dlpi_name);
        return 0;
    }
    return wrap->orig_cb(info, size, wrap->orig_data);
}

typedef int (*dl_iterate_phdr_fn)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
static dl_iterate_phdr_fn orig_dl_iterate_phdr = nullptr;  // NOLINT

static int hooked_dl_iterate_phdr(
        int (*callback)(struct dl_phdr_info*, size_t, void*), void* data) {
    dl_iter_wrap wrap = {callback, data};
    return orig_dl_iterate_phdr(filtered_dl_cb, &wrap);
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-init cleanup: rename Frida threads that spawned before hook installation
// ─────────────────────────────────────────────────────────────────────────────

static void cleanup_existing_frida_threads() {
    DIR* task_dir = opendir("/proc/self/task");
    if (!task_dir) return;

    char status_path[128], comm_path[128], line[128];
    struct dirent* ent;

    while ((ent = readdir(task_dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;

        snprintf(status_path, sizeof(status_path),
                 "/proc/self/task/%s/status", ent->d_name);
        FILE* f = fopen(status_path, "re");
        if (!f) continue;

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:\t", 6) != 0) continue;
            char* name = line + 6;
            char* nl = strchr(name, '\n');
            if (nl) *nl = '\0';

            if (is_frida_thread_name(name)) {
                LOGI("[anti_detect] Pre-hook Frida thread tid=%s name='%s'",
                     ent->d_name, name);
                snprintf(comm_path, sizeof(comm_path),
                         "/proc/self/task/%s/comm", ent->d_name);
                int fd = open(comm_path, O_WRONLY | O_CLOEXEC);
                if (fd >= 0) {
                    const char* rep = next_benign_name();
                    write(fd, rep, strlen(rep));
                    close(fd);
                    LOGI("[anti_detect] Renamed tid=%s -> '%s'", ent->d_name, rep);
                }
            }
            break;
        }
        fclose(f);
    }
    closedir(task_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

void install_anti_detect_hooks() {
    LOGI("[anti_detect] Installing hooks");
    void* addr;

#define HOOK(sym, hooked, orig) \
    addr = dlsym(RTLD_DEFAULT, sym); \
    if (addr) { \
        DobbyHook(addr, reinterpret_cast<void*>(hooked), \
                  reinterpret_cast<void**>(&orig)); \
        LOGI("[anti_detect] " sym " @ %p", addr); \
    } else { LOGE("[anti_detect] " sym " not found"); }

    HOOK("pthread_setname_np", hooked_pthread_setname_np, orig_pthread_setname_np)
    HOOK("prctl",              hooked_prctl,              orig_prctl)
    HOOK("readlinkat",         hooked_readlinkat,         orig_readlinkat)
    HOOK("dl_iterate_phdr",    hooked_dl_iterate_phdr,    orig_dl_iterate_phdr)

#undef HOOK

    LOGI("[anti_detect] Hook installation complete");
}

void remap_hooked_system_libs() {
    cleanup_existing_frida_threads();
    LOGI("[anti_detect] Post-init cleanup complete");
}
