#include "anti_detect.h"

#include <dobby.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <cinttypes>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "log.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Thread-name fingerprints
// ─────────────────────────────────────────────────────────────────────────────

static const char* const FRIDA_THREAD_NAMES[] = {
    "gum-js-loop",
    "gmain",
    "gdbus",
    "gum-dbus",
    "pool-frida",
    "linjector",
    nullptr,
};

static const char* const BENIGN_NAMES[] = {
    "pool-1-thread-1", "pool-2-thread-1", "pool-1-thread-2", "pool-3-thread-1",
    "pool-2-thread-2", "pool-4-thread-1", "pool-1-thread-3", "pool-5-thread-1",
};


static const char* const FRIDA_PIPE_ARTIFACTS[] = {
    "linjector", "frida-pipe", "frida-", nullptr,
};

static constexpr int BENIGN_COUNT = 8;
static std::atomic<int> g_name_counter { 0 };  // NOLINT

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

static const char* const MAPS_HIDE_LIBS[] = {
    "libc.so", "libart.so", nullptr,
};

static bool maps_line_targets_hidden_lib(const char* line) {
    for (int i = 0; MAPS_HIDE_LIBS[i]; i++) {
        if (strstr(line, MAPS_HIDE_LIBS[i])) return true;
    }
    return false;
}

static void maps_strip_path(char* line, size_t bufsz) {
    uintptr_t start = 0, end = 0, offset = 0;
    unsigned long inode = 0;
    char perms[8] = {}, dev[16] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %" SCNxPTR " %15s %lu",
               &start, &end, perms, &offset, dev, &inode) == 6) {
        snprintf(line, bufsz,
                 "%" PRIxPTR "-%" PRIxPTR " %s %" PRIxPTR " %s %lu\n",
                 start, end, perms, offset, dev, inode);
    }
}

// Open real path via raw syscall (cannot recurse into our hooks).
static int raw_open(const char* path) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
}

static int make_memfd(const char* tag) {
    return (int)syscall(__NR_memfd_create, tag, MFD_CLOEXEC);
}


// /proc/self/maps  — strip library paths from executable mappings.
static int create_filtered_maps_fd() {
    int rfd = raw_open("/proc/self/maps");
    if (rfd < 0) return -1;
    int mfd = make_memfd("maps");
    if (mfd < 0) { close(rfd); return -1; }

    FILE* f = fdopen(rfd, "r");
    if (!f) { close(rfd); close(mfd); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (maps_line_targets_hidden_lib(line))
            maps_strip_path(line, sizeof(line));
        write(mfd, line, strlen(line));
    }
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int create_filtered_status_fd(const char* path) {
    int rfd = raw_open(path);
    if (rfd < 0) return -1;
    int mfd = make_memfd("status");
    if (mfd < 0) { close(rfd); return -1; }

    FILE* f = fdopen(rfd, "r");
    if (!f) { close(rfd); close(mfd); return -1; }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            // Replace with zero regardless of actual value.
            write(mfd, "TracerPid:\t0\n", 13);
        } else {
            write(mfd, line, strlen(line));
        }
    }
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int create_filtered_tcp_fd(const char* path) {
    int rfd = raw_open(path);
    if (rfd < 0) return -1;
    int mfd = make_memfd("tcp");
    if (mfd < 0) { close(rfd); return -1; }

    FILE* f = fdopen(rfd, "r");
    if (!f) { close(rfd); close(mfd); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // Keep header and any line that does NOT reference Frida ports.
        if (!strstr(line, ":69A2") && !strstr(line, ":69A3") &&
            !strstr(line, ":69a2") && !strstr(line, ":69a3")) {
            write(mfd, line, strlen(line));
        } else {
            LOGI("[anti_detect] tcp filter: dropped Frida port line");
        }
    }
    fclose(f);
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int maybe_filtered_fd(const char* path) {
    if (!path) return -1;

    if (strcmp(path, "/proc/self/maps") == 0)
        return create_filtered_maps_fd();

    if (strcmp(path, "/proc/self/status") == 0)
        return create_filtered_status_fd(path);

    // /proc/self/task/<tid>/status
    if (strncmp(path, "/proc/self/task/", 16) == 0 && strstr(path + 16, "/status"))
        return create_filtered_status_fd(path);

    if (strcmp(path, "/proc/net/tcp")  == 0 ||
        strcmp(path, "/proc/net/tcp6") == 0)
        return create_filtered_tcp_fd(path);

    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook 1: pthread_setname_np
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
// Hook 2: prctl
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

typedef long (*ptrace_fn)(int, pid_t, void*, void*);
static ptrace_fn orig_ptrace = nullptr;  // NOLINT

static long hooked_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (request == PTRACE_TRACEME) {
        LOGI("[anti_detect] ptrace PTRACE_TRACEME -> spoofed 0");
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

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

// ── fopen hook ───────────────────────────────────────────────────────────────

typedef FILE* (*fopen_fn)(const char*, const char*);
static fopen_fn orig_fopen = nullptr;  // NOLINT

static FILE* hooked_fopen(const char* pathname, const char* mode) {
    int mfd = maybe_filtered_fd(pathname);
    if (mfd >= 0) {
        LOGI("[anti_detect] fopen filtered: %s", pathname);
        FILE* f = fdopen(mfd, mode && mode[0] ? mode : "r");
        if (f) return f;
        close(mfd);
    }
    return orig_fopen(pathname, mode);
}

// ── openat hook ──────────────────────────────────────────────────────────────

typedef int (*openat_fn)(int, const char*, int, ...);
static openat_fn orig_openat = nullptr;  // NOLINT

static int hooked_openat(int dirfd, const char* pathname, int flags, ...) {
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int mfd = maybe_filtered_fd(pathname);
        if (mfd >= 0) {
            LOGI("[anti_detect] openat filtered: %s", pathname);
            return mfd;
        }
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

static void cleanup_existing_frida_threads() {
    DIR* task_dir = opendir("/proc/self/task");
    if (!task_dir) return;

    char status_path[128], comm_path[128], line[128];
    struct dirent* ent;

    while ((ent = readdir(task_dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;

        snprintf(status_path, sizeof(status_path),
                 "/proc/self/task/%s/status", ent->d_name);
        // Use orig_fopen to skip our filtering for this internal read.
        FILE* f = orig_fopen ? orig_fopen(status_path, "re")
                             : fopen(status_path, "re");
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
    HOOK("ptrace",             hooked_ptrace,             orig_ptrace)
    HOOK("readlinkat",         hooked_readlinkat,         orig_readlinkat)
    HOOK("fopen",              hooked_fopen,              orig_fopen)
    HOOK("openat",             hooked_openat,             orig_openat)

#undef HOOK

    LOGI("[anti_detect] Hook installation complete");
}

void remap_hooked_system_libs() {
    cleanup_existing_frida_threads();
    LOGI("[anti_detect] Post-init setup complete");
}
