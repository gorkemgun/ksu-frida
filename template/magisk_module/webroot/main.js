const CONFIG_PATH = "/data/local/tmp/libsec/config.json";
const GADGET_CONFIG_PATH = "/data/local/tmp/libsec/libsecmon.config.so";

let config = { targets: [] };
let allApps = [];
let callbackId = 0;

// ── KSU exec wrapper using string-based callback registration ────────────────
function exec(cmd) {
    return new Promise(function (resolve) {
        var name = "_ksu_cb_" + (++callbackId);
        window[name] = function (errno, stdout, stderr) {
            delete window[name];
            resolve({ errno: errno, stdout: stdout, stderr: stderr });
        };
        ksu.exec(cmd, "{}", name);
    });
}

// ── Config I/O ───────────────────────────────────────────────────────────────
async function loadConfig() {
    var r = await exec("cat " + CONFIG_PATH);
    if (r.errno === 0 && r.stdout.trim().length > 0) {
        try {
            config = JSON.parse(r.stdout);
        } catch (e) {
            ksu.toast("Config parse error: " + e.message);
            return;
        }
    } else {
        var ex = await exec("cat /data/local/tmp/libsec/config.json.example");
        if (ex.errno === 0) {
            try { config = JSON.parse(ex.stdout); } catch (_) {}
        }
    }
    renderTargets();
}

async function saveConfig() {
    var json = JSON.stringify(config, null, 4);
    var escaped = json.replace(/'/g, "'\\''");
    var r = await exec("echo '" + escaped + "' > " + CONFIG_PATH);
    if (r.errno === 0) {
        ksu.toast("Config saved");
    } else {
        ksu.toast("Save failed: " + r.stderr);
    }
}

async function loadGadgetConfig() {
    var status = document.getElementById("gadget-status");
    var editor = document.getElementById("gadget-editor");
    var r = await exec("cat " + GADGET_CONFIG_PATH);
    if (r.errno === 0) {
        status.className = "status-ok";
        status.textContent = "OK";
        editor.value = r.stdout;
    } else {
        status.className = "status-err";
        status.textContent = "Not found";
        editor.value = '{"interaction":{"type":"listen","address":"0.0.0.0","port":27042}}';
    }
}

async function saveGadgetConfig() {
    var content = document.getElementById("gadget-editor").value;
    var escaped = content.replace(/'/g, "'\\''");
    var r = await exec("echo '" + escaped + "' > " + GADGET_CONFIG_PATH);
    if (r.errno === 0) {
        ksu.toast("Gadget config saved");
        loadGadgetConfig();
    } else {
        ksu.toast("Failed: " + r.stderr);
    }
}

// ── App list ─────────────────────────────────────────────────────────────────
var appLabels = {};

async function fetchApps() {
    // Get 3rd party packages with labels in one shot
    var r = await exec(
        "for p in $(pm list packages -3 | sed 's/package://'); do " +
        "l=$(dumpsys package \"$p\" | grep -m1 'nonLocalizedLabel=' | sed 's/.*nonLocalizedLabel=//;s/ .*//'); " +
        "echo \"$p|${l:-$p}\"; done"
    );
    if (r.errno === 0 && r.stdout.trim().length > 0) {
        allApps = [];
        r.stdout.split("\n").forEach(function (line) {
            line = line.trim();
            if (!line) return;
            var parts = line.split("|");
            var pkg = parts[0];
            var label = parts[1] || pkg;
            allApps.push(pkg);
            appLabels[pkg] = label;
        });
        allApps.sort(function (a, b) {
            return (appLabels[a] || a).localeCompare(appLabels[b] || b);
        });
    }
    // Fallback: just package names
    if (allApps.length === 0) {
        var r2 = await exec("pm list packages -3");
        if (r2.errno === 0 && r2.stdout.trim().length > 0) {
            allApps = r2.stdout.split("\n")
                .filter(function (l) { return l.indexOf("package:") === 0; })
                .map(function (l) { return l.replace("package:", "").trim(); })
                .sort();
        }
    }
}

function getAppLabel(pkg) {
    return appLabels[pkg] || pkg;
}

// ── Render ───────────────────────────────────────────────────────────────────
function renderTargets() {
    var container = document.getElementById("targets");
    container.innerHTML = "";

    if (config.targets.length === 0) {
        container.innerHTML = '<div class="empty">No targets configured. Tap + Add to start.</div>';
        return;
    }

    config.targets.forEach(function (t, i) {
        var div = document.createElement("div");
        div.className = "target";

        var childHtml = "";
        if (t.child_gating && t.child_gating.enabled) {
            var childLibs = (t.child_gating.injected_libraries || [])
                .map(function (l) { return l.path; }).join("\n");
            childHtml =
                '<div class="field"><label>Mode</label>' +
                '<select onchange="updateField(' + i + ',\'child_mode\',this.value)">' +
                '<option value="freeze"' + (t.child_gating.mode === "freeze" ? " selected" : "") + '>Freeze</option>' +
                '<option value="kill"' + (t.child_gating.mode === "kill" ? " selected" : "") + '>Kill</option>' +
                '<option value="inject"' + (t.child_gating.mode === "inject" ? " selected" : "") + '>Inject</option>' +
                '</select></div>' +
                '<div class="field"><label>Child Libraries</label>' +
                '<textarea onchange="updateField(' + i + ',\'child_libs\',this.value)">' + childLibs + '</textarea></div>';
        }

        var libs = t.injected_libraries.map(function (l) { return l.path; }).join("\n");

        div.innerHTML =
            '<div class="row">' +
                '<div><strong>' + getAppLabel(t.app_name) + '</strong>' +
                '<div style="font-size:11px;color:var(--text2)">' + t.app_name + '</div></div>' +
                '<div class="row row-gap">' +
                    '<label class="switch"><input type="checkbox"' + (t.enabled ? " checked" : "") +
                    ' onchange="updateField(' + i + ',\'enabled\',this.checked)"><span class="slider"></span></label>' +
                    '<button class="btn btn-danger btn-sm" onclick="removeTarget(' + i + ')">X</button>' +
                '</div>' +
            '</div>' +
            '<div class="row" style="margin-top:8px">' +
                '<span style="font-size:12px;color:var(--text2)">Kernel Evasion</span>' +
                '<label class="switch"><input type="checkbox"' + (t.kernel_assisted_evasion ? " checked" : "") +
                ' onchange="updateField(' + i + ',\'ksie\',this.checked)"><span class="slider"></span></label>' +
            '</div>' +
            '<div class="field"><label>Delay (ms)</label>' +
                '<input type="number" value="' + (t.start_up_delay_ms || 0) +
                '" onchange="updateField(' + i + ',\'delay\',this.value)"></div>' +
            '<div class="field"><label>Injected Libraries</label>' +
                '<textarea onchange="updateField(' + i + ',\'libs\',this.value)">' + libs + '</textarea></div>' +
            '<div class="child-panel">' +
                '<div class="row"><span style="font-size:12px">Child Gating</span>' +
                '<label class="switch"><input type="checkbox"' +
                (t.child_gating && t.child_gating.enabled ? " checked" : "") +
                ' onchange="updateField(' + i + ',\'child_enabled\',this.checked)"><span class="slider"></span></label>' +
                '</div>' + childHtml +
            '</div>';

        container.appendChild(div);
    });
}

// ── Data updates ─────────────────────────────────────────────────────────────
function updateField(i, field, value) {
    var t = config.targets[i];
    switch (field) {
        case "enabled":
            t.enabled = value;
            break;
        case "ksie":
            t.kernel_assisted_evasion = value;
            break;
        case "delay":
            t.start_up_delay_ms = parseInt(value) || 0;
            break;
        case "libs":
            t.injected_libraries = value.split("\n")
                .filter(function (l) { return l.trim() !== ""; })
                .map(function (l) { return { path: l.trim() }; });
            break;
        case "child_enabled":
            if (!t.child_gating) {
                t.child_gating = { enabled: false, mode: "freeze", injected_libraries: [] };
            }
            t.child_gating.enabled = value;
            renderTargets();
            break;
        case "child_mode":
            t.child_gating.mode = value;
            break;
        case "child_libs":
            t.child_gating.injected_libraries = value.split("\n")
                .filter(function (l) { return l.trim() !== ""; })
                .map(function (l) { return { path: l.trim() }; });
            break;
    }
}

function removeTarget(i) {
    config.targets.splice(i, 1);
    renderTargets();
}

function addTarget(pkg) {
    if (config.targets.some(function (t) { return t.app_name === pkg; })) {
        ksu.toast("Already added");
        return;
    }
    config.targets.push({
        app_name: pkg,
        enabled: true,
        kernel_assisted_evasion: false,
        start_up_delay_ms: 0,
        injected_libraries: [{ path: "/data/local/tmp/libsec/libsecmon.so" }],
        child_gating: { enabled: false, mode: "freeze", injected_libraries: [] }
    });
    renderTargets();
}

// ── Modal ────────────────────────────────────────────────────────────────────
function showAppList() {
    document.getElementById("app-modal").style.display = "flex";
    document.getElementById("app-search").value = "";
    renderAppList();
}

function closeAppModal() {
    document.getElementById("app-modal").style.display = "none";
}

function renderAppList() {
    var list = document.getElementById("app-list");
    var search = document.getElementById("app-search").value.toLowerCase();

    var filtered = allApps.filter(function (a) {
        var label = (appLabels[a] || "").toLowerCase();
        return a.toLowerCase().indexOf(search) !== -1 || label.indexOf(search) !== -1;
    });

    if (filtered.length === 0) {
        list.innerHTML = '<div class="empty">No apps found</div>';
        return;
    }

    list.innerHTML = "";
    filtered.forEach(function (app) {
        var row = document.createElement("div");
        row.className = "app-row";
        var label = getAppLabel(app);
        row.innerHTML = '<div><strong>' + label + '</strong></div>' +
            '<div class="app-label">' + app + '</div>';
        row.onclick = function () {
            addTarget(app);
            closeAppModal();
        };
        list.appendChild(row);
    });
}

// ── Init ─────────────────────────────────────────────────────────────────────
window.onload = function () {
    if (typeof ksu === "undefined") {
        document.body.innerHTML = '<div style="text-align:center;padding:40px;color:#f44336;">' +
            'This page must be opened in KernelSU Manager.</div>';
        return;
    }

    document.getElementById("btn-add").onclick = showAppList;
    document.getElementById("btn-save").onclick = saveConfig;
    document.getElementById("btn-reload").onclick = function () { loadConfig(); loadGadgetConfig(); };
    document.getElementById("btn-save-gadget").onclick = saveGadgetConfig;
    document.getElementById("btn-close-modal").onclick = closeAppModal;
    document.getElementById("app-search").oninput = renderAppList;

    loadConfig();
    loadGadgetConfig();
    fetchApps();
};
