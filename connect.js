document.addEventListener("DOMContentLoaded", () => {
    initVercelUrl();
    loadAdminKey();
    renderKeyList();
});

function initVercelUrl() {
    const apiUrl = window.location.origin + "/api/connect";
    document.getElementById("vercelUrl").innerText = apiUrl;
}

function copyVercelUrl() {
    const urlText = document.getElementById("vercelUrl").innerText;
    navigator.clipboard.writeText(urlText).then(() => {
        showToast("✅ Database Vercel URL berhasil disalin!");
    }).catch(() => {
        showToast("❌ Gagal menyalin URL", true);
    });
}

function saveAdminKey() {
    const adminKey = document.getElementById("adminKeyInput").value.trim();
    if (!adminKey) {
        alert("Admin API Key tidak boleh kosong!");
        return;
    }
    localStorage.setItem("admin_api_key", adminKey);
    showToast("🔑 Admin Key berhasil disimpan!");
}

function loadAdminKey() {
    const savedKey = localStorage.getItem("admin_api_key");
    if (savedKey) {
        document.getElementById("adminKeyInput").value = savedKey;
    }
}

function toggleShowAdminKey() {
    const input = document.getElementById("adminKeyInput");
    input.type = input.type === "password" ? "text" : "password";
}

function getStoredKeys() {
    const keys = localStorage.getItem("generated_api_keys");
    return keys ? JSON.parse(keys) : [];
}

function saveKeysToStorage(keys) {
    localStorage.setItem("generated_api_keys", JSON.stringify(keys));
}

function generateRandomKey(prefix = "key") {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = prefix + "_";
    for (let i = 0; i < 32; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function createNewKey() {
    const labelInput = document.getElementById("keyLabel");
    const label = labelInput.value.trim() || "Untitled Key";

    const newKeyObj = {
        id: Date.now(),
        label: label,
        keyValue: generateRandomKey("vdb"),
        createdAt: new Date().toLocaleString("id-ID")
    };

    const currentKeys = getStoredKeys();
    currentKeys.unshift(newKeyObj);
    saveKeysToStorage(currentKeys);

    labelInput.value = "";
    renderKeyList();
    showToast("✨ Key baru berhasil dibuat!");
}

function deleteKey(id) {
    if (confirm("Hapus key ini?")) {
        let currentKeys = getStoredKeys();
        currentKeys = currentKeys.filter(k => k.id !== id);
        saveKeysToStorage(currentKeys);
        renderKeyList();
        showToast("🗑️ Key berhasil dihapus");
    }
}

function copyKeyToClipboard(keyValue) {
    navigator.clipboard.writeText(keyValue).then(() => {
        showToast("📋 Key disalin ke clipboard!");
    });
}

function renderKeyList() {
    const keyListElement = document.getElementById("keyList");
    const keys = getStoredKeys();

    if (keys.length === 0) {
        keyListElement.innerHTML = `<p style="color: var(--text-muted); text-align: center; padding: 10px;">Belum ada key yang dibuat.</p>`;
        return;
    }

    keyListElement.innerHTML = keys.map(k => `
        <div class="key-item">
            <div class="key-info">
                <span class="key-name">${escapeHtml(k.label)}</span>
                <span class="key-value">${k.keyValue}</span>
                <span class="key-date">Dibuat: ${k.createdAt}</span>
            </div>
            <div class="action-row">
                <button class="btn btn-secondary" onclick="copyKeyToClipboard('${k.keyValue}')">📋 Copy</button>
                <button class="btn btn-danger" onclick="deleteKey(${k.id})">🗑️ Hapus</button>
            </div>
        </div>
    `).join("");
}

function showToast(message, isError = false) {
    const toast = document.getElementById("toast");
    toast.innerText = message;
    toast.style.backgroundColor = isError ? "var(--danger-color)" : "var(--success-color)";
    toast.style.display = "block";
    setTimeout(() => { toast.style.display = "none"; }, 3000);
}

function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
