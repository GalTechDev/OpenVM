let currentPath = '/';

function loadFiles(path) {
    const containerIdElement = document.getElementById('activeContainerId');
    if (!containerIdElement) {
        console.error("activeContainerId element not found!");
        return;
    }
    const containerId = containerIdElement.value;
    if (!containerId) {
        console.error("Container ID is empty!");
        return;
    }

    fetch('/api/container/files', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_id: containerId, path: path })
    })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                return;
            }
            currentPath = data.current_path;
            renderBreadcrumbs(currentPath);
            renderFileList(data.files);
            document.getElementById('fileExplorerCard').style.display = 'block';
        });
}

function renderBreadcrumbs(path) {
    const parts = path.split('/').filter(p => p);
    const crumbs = document.getElementById('fileBreadcrumbs');
    crumbs.innerHTML = '<span class="crumb" onclick="loadFiles(\'/\')">/</span>';

    let builtPath = '';
    parts.forEach((part, index) => {
        builtPath += '/' + part;
        const span = document.createElement('span');
        span.className = 'crumb';
        span.innerText = part + (index < parts.length - 1 ? '/' : '');
        // simple closure fix
        const p = builtPath;
        span.onclick = () => loadFiles(p);
        crumbs.appendChild(span);
        // Separator
        if (index < parts.length - 1) {
            // actually the slash is usually part of the separator visuals
            // but let's just keep it simple
        }
    });
}

// ... Load logic ...

function renderFileList(files) {
    const tbody = document.getElementById('fileListBody');
    tbody.innerHTML = '';

    if (currentPath !== '/') {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td colspan="4" style="cursor: pointer;" onclick="goUp()">
                <i class="ri-arrow-go-back-line"></i> ..
            </td>
        `;
        tbody.appendChild(tr);
    }

    files.forEach(f => {
        const tr = document.createElement('tr');
        const icon = f.type === 'dir' ? '<i class="ri-folder-fill" style="color: #fbbf24;"></i>' : '<i class="ri-file-text-line"></i>';

        // Name Link
        const nameLink = f.type === 'dir' ?
            `<a href="#" onclick="loadFiles('${currentPath === '/' ? '' : currentPath}/${f.name}'); return false;">${f.name}</a>` :
            f.name;

        // Actions
        // Download (File or Dir), Rename, Delete
        const fullPath = (currentPath === '/' ? '' : currentPath) + '/' + f.name;

        const actions = `
            <button class="btn-icon primary" onclick="downloadFile('${f.name}', '${f.type}')" title="Download"><i class="ri-download-line"></i></button>
            <button class="btn-icon warning" onclick="openRenameModal('${f.name}')" title="Rename"><i class="ri-edit-line"></i></button>
            <button class="btn-icon danger" onclick="deleteFile('${f.name}')" title="Delete"><i class="ri-delete-bin-line"></i></button>
        `;

        tr.innerHTML = `
            <td>${icon} ${nameLink}</td>
            <td>${f.type === 'dir' ? '-' : formatSize(parseInt(f.size))}</td>
            <td><span class="mono" style="font-size: 0.8em">${f.perms}</span></td>
            <td class="action-buttons-cell"><div class="action-buttons">${actions}</div></td>
        `;
        tbody.appendChild(tr);
    });
}

// Utility Functions
function goUp() {
    const parts = currentPath.split('/').filter(p => p);
    parts.pop();
    const parent = '/' + parts.join('/');
    loadFiles(parent);
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function downloadFile(filename, type) {
    const containerId = document.getElementById('activeContainerId').value;
    const fullPath = (currentPath === '/' ? '' : currentPath) + '/' + filename;

    let url = `/api/container/download?container_id=${containerId}&path=${fullPath}`;
    if (type === 'dir') url += '&type=dir'; // Hint to backend

    window.location.href = url;
}

// Modals
function openNewFolderModal() {
    document.getElementById('newFolderModal').style.display = 'flex';
    document.getElementById('newFolderName').focus();
}

function openRenameModal(filename) {
    document.getElementById('renameOldPath').value = (currentPath === '/' ? '' : currentPath) + '/' + filename;
    document.getElementById('renameNewName').value = filename;
    document.getElementById('renameModal').style.display = 'flex';
    document.getElementById('renameNewName').focus();
}

function closeFileModal(id) {
    document.getElementById(id).style.display = 'none';
}

function createFolder() {
    const name = document.getElementById('newFolderName').value;
    if (!name) return;

    const containerId = document.getElementById('activeContainerId').value;
    const path = (currentPath === '/' ? '' : currentPath) + '/' + name;

    fetch('/api/container/mkdir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_id: containerId, path: path })
    }).then(res => res.json()).then(data => {
        if (data.error) alert(data.error);
        else {
            closeFileModal('newFolderModal');
            document.getElementById('newFolderName').value = '';
            loadFiles(currentPath);
        }
    });
}

function submitRename() {
    const oldPath = document.getElementById('renameOldPath').value;
    const newName = document.getElementById('renameNewName').value;
    if (!newName) return;

    // Construct new path: parent of oldPath + newName
    // oldPath: /foo/bar.txt -> parent: /foo
    const parent = oldPath.substring(0, oldPath.lastIndexOf('/'));
    const newPath = (parent === '' ? '' : parent) + '/' + newName;

    const containerId = document.getElementById('activeContainerId').value;

    fetch('/api/container/rename', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_id: containerId, old_path: oldPath, new_path: newPath })
    }).then(res => res.json()).then(data => {
        if (data.error) alert(data.error);
        else {
            closeFileModal('renameModal');
            loadFiles(currentPath);
        }
    });
}

async function deleteFile(filename) {
    if (!await showConfirm('Delete File', `Delete ${filename}?`)) return;

    const containerId = document.getElementById('activeContainerId').value;
    const path = (currentPath === '/' ? '' : currentPath) + '/' + filename;

    fetch('/api/container/delete_file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_id: containerId, path: path })
    }).then(res => res.json()).then(data => {
        if (data.error) alert(data.error);
        else {
            loadFiles(currentPath);
        }
    });
}

function uploadFile() {
    const fileInput = document.getElementById('fileUploadInput');
    const file = fileInput.files[0];
    if (!file) return;

    const containerId = document.getElementById('activeContainerId').value;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('container_id', containerId);
    formData.append('path', currentPath);

    // Show loading state?
    // For now simple alert on finish

    fetch('/api/container/upload', {
        method: 'POST',
        body: formData // Content-Type is auto-set to multipart/form-data
    })
        .then(res => res.json())
        .then(data => {
            // Clear input
            fileInput.value = '';

            if (data.error) {
                alert(data.error);
            } else {
                loadFiles(currentPath);
            }
        })
        .catch(err => {
            console.error(err);
            alert("Upload failed");
        });
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    // Modal Close Logic
    window.onclick = function (event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = "none";
        }
    }

    if (document.getElementById('activeContainerId')) {
        loadFiles('/');
    }
});
