const CONFIG_PATH = "/data/local/tmp/libsec/config.json";
const GADGET_CONFIG_PATH = "/data/local/tmp/libsec/libsecmon.config.so";
let config = { targets: [] };
let allApps = [];

async function exec(cmd) {
    return new Promise((resolve) => {
        ksu.exec(cmd, (errno, stdout, stderr) => {
            resolve({ errno, stdout, stderr });
        });
    });
}

async function loadGadgetConfig() {
    const { errno, stdout, stderr } = await exec(`cat ${GADGET_CONFIG_PATH}`);
    const status = document.getElementById('gadget-config-status');
    const editor = document.getElementById('gadget-config-editor');
    if (errno === 0) {
        status.innerHTML = '<span style="color:green;">Config exists and readable</span>';
        editor.value = stdout;
    } else {
        status.innerHTML = '<span style="color:red;">Config not found or error: ' + stderr + '</span>';
        editor.value = "";
    }
}

async function saveGadgetConfig() {
    const content = document.getElementById('gadget-config-editor').value;
    const escaped = content.replace(/'/g, "'\\''");
    const { errno, stdout, stderr } = await exec(`echo '${escaped}' > ${GADGET_CONFIG_PATH}`);
    if (errno === 0) {
        ksu.toast("Gadget config saved");
        loadGadgetConfig();
    } else {
        ksu.toast("Failed to save gadget config: " + stderr);
    }
}

async function loadConfig() {
    const { errno, stdout, stderr } = await exec(`cat ${CONFIG_PATH}`);
    if (errno === 0) {
        try {
            config = JSON.parse(stdout);
        } catch (e) {
            console.error("Failed to parse config", e);
            ksu.toast("Failed to parse config: " + e.message);
        }
    } else {
        console.log("Config not found or readable, using default");
        // Try to load example if real one doesn't exist
        const example = await exec(`cat /data/local/tmp/libsec/config.json.example`);
        if (example.errno === 0) {
            config = JSON.parse(example.stdout);
        }
    }
    renderTargets();
}

async function saveConfig() {
    const configStr = JSON.stringify(config, null, 4);
    // Escape for shell
    const escapedConfig = configStr.replace(/'/g, "'\\''");
    const { errno, stdout, stderr } = await exec(`echo '${escapedConfig}' > ${CONFIG_PATH}`);
    if (errno === 0) {
        ksu.toast("Config saved successfully");
    } else {
        ksu.toast("Failed to save config: " + stderr);
    }
}

async function fetchApps() {
    // Get list of installed apps
    const { errno, stdout, stderr } = await exec("pm list packages -e");
    if (errno === 0) {
        allApps = stdout.split('\n')
            .filter(line => line.startsWith('package:'))
            .map(line => line.replace('package:', '').trim());
    }
}

function renderTargets() {
    const container = document.getElementById('targets-container');
    container.innerHTML = '';

    config.targets.forEach((target, index) => {
        const item = document.createElement('div');
        item.className = 'target-item';
        item.innerHTML = `
            <div class="row">
                <strong>${target.app_name}</strong>
                <div class="row" style="gap: 8px;">
                    <label class="switch">
                        <input type="checkbox" ${target.enabled ? 'checked' : ''} onchange="toggleTarget(${index}, this.checked)">
                        <span class="slider"></span>
                    </label>
                    <button class="btn btn-danger" onclick="removeTarget(${index})">Remove</button>
                </div>
            </div>
            <div>
                <label>Delay (ms):</label>
                <input type="number" value="${target.start_up_delay_ms}" onchange="updateDelay(${index}, this.value)">
            </div>
            <div>
                <label>Injected Libraries (one per line):</label>
                <textarea style="width:100%; height:60px;" onchange="updateLibs(${index}, this.value)">${target.injected_libraries.map(l => l.path).join('\n')}</textarea>
            </div>
            <div class="child-gating-panel">
                <div class="row">
                    <span>Child Gating</span>
                    <label class="switch">
                        <input type="checkbox" ${target.child_gating?.enabled ? 'checked' : ''} onchange="toggleChildGating(${index}, this.checked)">
                        <span class="slider"></span>
                    </label>
                </div>
                ${target.child_gating?.enabled ? `
                    <label>Mode:</label>
                    <select onchange="updateChildGatingMode(${index}, this.value)">
                        <option value="freeze" ${target.child_gating.mode === 'freeze' ? 'selected' : ''}>Freeze</option>
                        <option value="relax" ${target.child_gating.mode === 'relax' ? 'selected' : ''}>Relax</option>
                    </select>
                    <label>Child Libs (one per line):</label>
                    <textarea style="width:100%; height:40px;" onchange="updateChildLibs(${index}, this.value)">${target.child_gating.injected_libraries?.map(l => l.path).join('\n') || ''}</textarea>
                ` : ''}
            </div>
        `;
        container.appendChild(item);
    });
}

function toggleTarget(index, enabled) {
    config.targets[index].enabled = enabled;
}

function removeTarget(index) {
    config.targets.splice(index, 1);
    renderTargets();
}

function updateDelay(index, value) {
    config.targets[index].start_up_delay_ms = parseInt(value) || 0;
}

function updateLibs(index, value) {
    config.targets[index].injected_libraries = value.split('\n')
        .filter(line => line.trim() !== '')
        .map(line => ({ path: line.trim() }));
}

function toggleChildGating(index, enabled) {
    if (!config.targets[index].child_gating) {
        config.targets[index].child_gating = { enabled: false, mode: 'freeze', injected_libraries: [] };
    }
    config.targets[index].child_gating.enabled = enabled;
    renderTargets();
}

function updateChildGatingMode(index, value) {
    config.targets[index].child_gating.mode = value;
}

function updateChildLibs(index, value) {
    config.targets[index].child_gating.injected_libraries = value.split('\n')
        .filter(line => line.trim() !== '')
        .map(line => ({ path: line.trim() }));
}

function showAppList() {
    document.getElementById('app-modal').style.display = 'flex';
    renderAppList();
}

function closeAppModal() {
    document.getElementById('app-modal').style.display = 'none';
}

function renderAppList() {
    const list = document.getElementById('app-list');
    list.innerHTML = '';
    const search = document.getElementById('app-search').value.toLowerCase();
    
    allApps.filter(app => app.toLowerCase().includes(search)).forEach(app => {
        const item = document.createElement('div');
        item.className = 'app-item';
        item.innerText = app;
        item.onclick = () => {
            addTarget(app);
            closeAppModal();
        };
        list.appendChild(item);
    });
}

function filterApps() {
    renderAppList();
}

function addTarget(packageName) {
    if (config.targets.some(t => t.app_name === packageName)) {
        ksu.toast("App already in list");
        return;
    }
    config.targets.push({
        app_name: packageName,
        enabled: true,
        start_up_delay_ms: 0,
        injected_libraries: [{ path: "/data/local/tmp/libsec/libsecmon.so" }],
        child_gating: { enabled: false, mode: "freeze", injected_libraries: [] }
    });
    renderTargets();
}

// Initialize
window.onload = async () => {
    if (typeof ksu === 'undefined') {
        alert("This page must be opened in KernelSU Manager.");
        return;
    }
    await loadConfig();
    await loadGadgetConfig();
    await fetchApps();
};
