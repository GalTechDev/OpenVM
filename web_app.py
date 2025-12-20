from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import sys
import os
import bcrypt
import struct
import psutil
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('web_app')

try:
    import pty
    import termios
    import fcntl
except ImportError:
    # Windows compatibility
    pty = None
    termios = None
    fcntl = None

from docker_utils import DockerHelper
from terminal_manager import TerminalManager

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_demo' 
socketio = SocketIO(app, async_mode='gevent')

DB_PATH = 'data/db.sqlite'

def init_database():
    """Initialize database and run all migrations automatically."""
    # Create data directory if not exists
    if not os.path.exists('data'):
        os.makedirs('data')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            container_id TEXT,
            is_admin INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0
        )
    ''')
    
    # Create containers table
    c.execute('''
        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            container_docker_id TEXT,
            name TEXT,
            status TEXT DEFAULT 'stopped',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            limits_enabled INTEGER DEFAULT 0,
            ram_limit_mb INTEGER DEFAULT NULL,
            cpu_limit_percent INTEGER DEFAULT NULL,
            storage_limit_mb INTEGER DEFAULT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Create volume_limits table
    c.execute('''
        CREATE TABLE IF NOT EXISTS volume_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            volume_name TEXT UNIQUE NOT NULL,
            size_limit_mb INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

def check_docker_permissions():
    """Check if Docker is accessible and return status."""
    try:
        # Use DockerHelper to respect config (sudo vs non-sudo)
        DockerHelper.run_command(["ps"])
        return {"ok": True, "message": "Docker accessible"}
    except Exception as e:
        return {"ok": False, "message": f"Docker error: {str(e)}"}

def is_setup_complete():
    """Check if initial setup is complete (at least one admin exists)."""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1')
        count = c.fetchone()[0]
        conn.close()
        return count > 0
    except:
        return False

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database on startup
init_database()

@app.route('/')
def index():
    # Check if setup is complete
    if not is_setup_complete():
        return redirect(url_for('setup'))
    
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup page - create first admin user."""
    from docker_utils import get_config, save_config
    
    # If setup already complete, redirect to login
    if is_setup_complete():
        return redirect(url_for('index'))
    
    # Get current config
    current_config = get_config()
    
    # Check Docker permissions based on current mode
    docker_status = check_docker_permissions()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        docker_mode = request.form.get('docker_mode', 'host')
        
        errors = []
        
        if not username:
            errors.append("Username is required")
        if len(username) < 3:
            errors.append("Username must be at least 3 characters")
        if not password:
            errors.append("Password is required")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters")
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        if errors:
            return render_template('setup.html', 
                                   errors=errors, 
                                   docker_status=docker_status,
                                   username=username,
                                   docker_mode=docker_mode)
        
        # Save Docker configuration
        config = {
            "docker_mode": docker_mode,
            "use_sudo": docker_mode == "host"
        }
        save_config(config)
        
        # Create admin user
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)',
                     (username, password_hash))
            conn.commit()
            conn.close()
            
            # Auto-login the new admin
            session['username'] = username
            session['is_admin'] = True
            session['is_blocked'] = False
            
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError:
            return render_template('setup.html',
                                   errors=["Username already exists"],
                                   docker_status=docker_status,
                                   username=username,
                                   docker_mode=docker_mode)
    
    return render_template('setup.html', 
                           docker_status=docker_status,
                           docker_mode=current_config.get('docker_mode', 'host'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT password_hash, is_admin, is_blocked FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password.encode(), row['password_hash'].encode()):
        session['username'] = username
        session['is_admin'] = row['is_admin']
        
        if row['is_blocked']:
             session['is_blocked'] = True
             # Still allow login to see they are blocked? Or just deny?
             # User said "cannot start/stop/access", implies they might see dashboard but it's disabled.
             # We'll store it in session.
        else:
             session['is_blocked'] = False

        if row['is_admin']:
             return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    return render_template('login.html', error="Invalid credentials")

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))

@app.route('/admin')
def admin_dashboard():
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    return render_template('admin.html', username=session['username'], is_admin=True)

@app.route('/api/admin/system_stats')
def system_stats():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return jsonify({
        "cpu": round(cpu_percent, 1),
        "memory": round(memory.percent, 1),
        "memory_used": round(memory.used / (1024**3), 1),  # GB
        "memory_total": round(memory.total / (1024**3), 1),  # GB
        "disk": round(disk.percent, 1),
        "disk_used": round(disk.used / (1024**3), 1),  # GB
        "disk_total": round(disk.total / (1024**3), 1)  # GB
    })

@app.route('/api/admin/users')
def list_users():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT username, is_admin, is_blocked, rowid as id FROM users')
    rows = c.fetchall()
    
    users = []
    for r in rows:
        # Get containers for this user
        c.execute('SELECT container_docker_id, status, name FROM containers WHERE user_id = ?', (r['id'],))
        cont_rows = c.fetchall()
        
        user_containers = []
        for cr in cont_rows:
            cid = cr['container_docker_id']
            name = cr['name']
            try:
                status = DockerHelper.get_status(cid)
                # Get stats only for running containers
                if status == 'running':
                    stats = DockerHelper.get_container_stats(cid)
                else:
                    stats = {"cpu": "--", "mem_usage": "--", "mem_percent": "--"}
            except:
                status = "error"
                stats = {"cpu": "--", "mem_usage": "--", "mem_percent": "--"}
            user_containers.append({
                'id': cid, 
                'status': status, 
                'name': name,
                'cpu': stats['cpu'],
                'mem_usage': stats['mem_usage'],
                'mem_percent': stats['mem_percent']
            })

        # Backward compatibility for frontend: use first container as "main"
        main_cid = user_containers[0]['id'] if user_containers else None
        main_status = user_containers[0]['status'] if user_containers else "none"

        users.append({
            "username": r['username'],
            "user_id": r['id'],
            "container_id": main_cid, 
            "containers": user_containers, # New field
            "is_admin": bool(r['is_admin']),
            "is_blocked": bool(r['is_blocked']),
            "status": main_status
        })
    conn.close()
    return jsonify({"users": users})

@app.route('/api/admin/container/create', methods=['POST'])
def create_container_api():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    username = data.get('username')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT rowid as id FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
        
    user_id = row['id']
    ports = data.get('ports', '') # "80:80,8080:8080"
    yaml_config = data.get('yaml_config', '')
    
    try:
        # Network per user
        network_name = f"openvm_net_{username}"
        DockerHelper.create_network(network_name)

        # Create container 
        import uuid
        unique_suffix = str(uuid.uuid4())[:8]
        # This string passed to DockerHelper becomes part of openvm_client_{suffix}
        # and hostname. safely unique.
        docker_ref = f"{username}-{unique_suffix}"
        
        # Display name check
        display_name = data.get('name') or docker_ref
        
        container_id = DockerHelper.create_container(docker_ref, ports=ports, network=network_name, yaml_config=yaml_config)
        
        # We should store ports in DB if we want to show them later. 
        # For now, we rely on Docker inspect for viewing.
        
        c.execute('INSERT INTO containers (user_id, container_docker_id, name) VALUES (?, ?, ?)',
                  (user_id, container_id, display_name))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "created", "container_id": container_id})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/update_ports', methods=['POST'])
def update_ports():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    
    data = request.json
    container_id = data.get('container_id')
    ports = data.get('ports', '')
    
    if not container_id: return jsonify({"error": "Missing container_id"}), 400
    
    # Verify ownership
    if not verify_container_access(session['username'], container_id):
         return jsonify({"error": "Unauthorized"}), 403
         
    # WARNING: This recreates the container!
    # We need to reconstruct the params.
    try:
        # Get existing info to preserve name/network
        info = DockerHelper.inspect(container_id)
        if not info: return jsonify({"error": "Container not found"}), 404
        
        # Extract "suffix" from container name openvm_client_{suffix}
        name = info['Name'] # /openvm_client_...
        if name.startswith('/'): name = name[1:]
        if not name.startswith('openvm_client_'):
             return jsonify({"error": "Invalid container naming, cannot recreate safely"}), 400
             
        docker_ref = name.replace('openvm_client_', '')
        
        # Network
        networks = info['NetworkSettings']['Networks']
        network_name = list(networks.keys())[0] if networks else None
        
        # Recreate
        new_id = DockerHelper.create_container(docker_ref, ports=ports, network=network_name)
        
        # Update DB ID
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('UPDATE containers SET container_docker_id = ? WHERE container_docker_id = ?', (new_id, container_id))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "updated", "new_id": new_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/create_user', methods=['POST'])
def create_user():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
        
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    
    if not username or not password:
         return jsonify({"error": "Missing fields"}), 400

    # Call manager function (code reuse via subprocess or import)
    # Importing is cleaner but we need to ensure threadsafety with sqlite?
    # subprocess is safer for isolation.
    
    cmd = [sys.executable, 'manager.py', 'add_user', username, password]
    if is_admin:
        cmd.append('--admin')
        
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        return jsonify({"status": "created"})
    else:
        return jsonify({"error": res.stdout + res.stderr}), 500

@app.route('/api/admin/delete_user', methods=['POST'])
def delete_user_api():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
        
    data = request.json
    username = data.get('username')
    
    if username == session['username']:
        return jsonify({"error": "Cannot delete yourself"}), 400

    cmd = [sys.executable, 'manager.py', 'delete_user', username]
    res = subprocess.run(cmd, capture_output=True, text=True)
    
    if res.returncode == 0:
        return jsonify({"status": "deleted"})
    else:
        return jsonify({"error": res.stdout + res.stderr}), 500

@app.route('/api/admin/user/block', methods=['POST'])
def block_user():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    username = data.get('username')
    block_status = data.get('block', True) # True to block, False to unblock
    
    conn = get_db_connection()
    c = conn.cursor()
    # Use 1 for True, 0 for False
    val = 1 if block_status else 0
    c.execute('UPDATE users SET is_blocked = ? WHERE username = ?', (val, username))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/admin/edit_user', methods=['POST'])
def edit_user():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')  # Can be None
    is_admin = data.get('is_admin', False)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Update is_admin
    admin_val = 1 if is_admin else 0
    c.execute('UPDATE users SET is_admin = ? WHERE username = ?', (admin_val, username))
    
    # Update password if provided
    if password:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hashed.decode('utf-8'), username))
    
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route('/api/container/files', methods=['POST'])
def list_files():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    
    data = request.get_json(force=True, silent=True)
    if not data:
        print(f"DEBUG: Invalid JSON received. Body: {request.data}")
        return jsonify({"error": "Invalid request body"}), 400
        
    container_id = data.get('container_id')
    path = data.get('path', '/')
    
    # Ownership Check
    target_container = verify_container_access(session['username'], container_id)
    if not target_container:
         return jsonify({"error": "Unauthorized container access"}), 403

    files = DockerHelper.list_files(container_id, path)
    return jsonify({"files": files, "current_path": path})

@app.route('/api/container/mkdir', methods=['POST'])
def mkdir():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    data = request.get_json(force=True, silent=True) or {}
    container_id = data.get('container_id')
    path = data.get('path')
    if not container_id or not path: return jsonify({"error": "Missing fields"}), 400
    if not verify_container_access(session['username'], container_id): return jsonify({"error": "Unauthorized"}), 403
    try:
        DockerHelper.create_directory(container_id, path)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/rename', methods=['POST'])
def rename():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    data = request.get_json(force=True, silent=True) or {}
    container_id = data.get('container_id')
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    if not container_id or not old_path or not new_path: return jsonify({"error": "Missing fields"}), 400
    if not verify_container_access(session['username'], container_id): return jsonify({"error": "Unauthorized"}), 403
    try:
        DockerHelper.rename_path(container_id, old_path, new_path)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/delete_file', methods=['POST'])
def delete_file():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    data = request.get_json(force=True, silent=True) or {}
    container_id = data.get('container_id')
    path = data.get('path')
    if not container_id or not path: return jsonify({"error": "Missing fields"}), 400
    if not verify_container_access(session['username'], container_id): return jsonify({"error": "Unauthorized"}), 403
    try:
        DockerHelper.delete_path(container_id, path)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/download', methods=['GET'])
def download_file():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    if session.get('is_blocked'): return "Account blocked", 403
        
    container_id = request.args.get('container_id')
    path = request.args.get('path')
    type_ = request.args.get('type') # 'dir' or 'file'
    
    if not container_id or not path:
        return "Missing parameters", 400
        
    if not verify_container_access(session['username'], container_id):
        return "Unauthorized", 403

    try:
        if type_ == 'dir':
            # Stream tar
            cmd = DockerHelper.get_archive_cmd(container_id, path)
            # Use Popen to get stdout stream
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Check for immediate errors? hard with streaming.
            # We trust docker cp - works for file or dir, outputs tar stream.
            
            return send_file(
                process.stdout,
                as_attachment=True,
                download_name=f"{os.path.basename(path)}.tar"
            )
            
        data = DockerHelper.read_file_bytes(container_id, path)
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=os.path.basename(path)
        )
    except Exception as e:
        return str(e), 500

@app.route('/api/container/upload', methods=['POST'])
def upload_file():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
    
    container_id = request.form.get('container_id')
    path = request.form.get('path', '/')
    file = request.files.get('file')
    
    if not container_id or not file:
        return jsonify({"error": "Missing container_id or file"}), 400
        
    if not verify_container_access(session['username'], container_id):
        return jsonify({"error": "Unauthorized"}), 403

    filename = file.filename
    # Temporary save locally
    local_path = os.path.join('/tmp', filename)
    file.save(local_path)
    
    # Destination in container
    dest_path = os.path.join(path, filename)
    
    try:
        DockerHelper.put_file(container_id, local_path, dest_path)
        os.remove(local_path) # cleanup
        return jsonify({"status": "success"})
    except Exception as e:
        if os.path.exists(local_path): os.remove(local_path)
        return jsonify({"error": str(e)}), 500

# Admin Volume Management API
@app.route('/api/admin/volumes', methods=['GET'])
def admin_list_volumes():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    # List all openvm volumes
    prefix = "openvm_vol_"
    
    try:
        volumes = DockerHelper.list_volumes(prefix=prefix)
        # Parse owner from name
        for v in volumes:
            # Format: openvm_vol_username_volumename
            parts = v['name'].replace('openvm_vol_', '').split('_', 1)
            v['owner'] = parts[0] if parts else 'unknown'
            v['display_name'] = parts[1] if len(parts) > 1 else v['name']
        return jsonify({"volumes": volumes})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/volumes/create', methods=['POST'])
def admin_create_volume():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    username = data.get('username', '').strip()
    volume_name = data.get('name', '').strip()
    
    if not username or not volume_name:
        return jsonify({"error": "Username and volume name required"}), 400
    
    # Sanitize name
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', volume_name):
        return jsonify({"error": "Invalid volume name. Use only letters, numbers, underscores, hyphens."}), 400
    
    full_name = f"openvm_vol_{username}_{volume_name}"
    
    try:
        DockerHelper.create_volume(full_name)
        return jsonify({"status": "success", "volume_name": full_name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/volumes/delete', methods=['POST'])
def admin_delete_volume():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    volume_name = data.get('name', '')
    
    # Admin can delete any openvm volume
    if not volume_name.startswith('openvm_vol_'):
        return jsonify({"error": "Can only delete openvm volumes"}), 400
    
    try:
        DockerHelper.delete_volume(volume_name)
        # Also remove from volume_limits table
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('DELETE FROM volume_limits WHERE volume_name = ?', (volume_name,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Volume Monitoring API
@app.route('/api/admin/volumes/monitoring', methods=['GET'])
def get_volumes_monitoring():
    """Get all volumes with their sizes and limits for monitoring."""
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Get volumes with sizes
        volumes = DockerHelper.get_all_volumes_with_sizes(prefix="openvm_vol_")
        
        # Get limits from database
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT volume_name, size_limit_mb FROM volume_limits')
        limits = {row['volume_name']: row['size_limit_mb'] for row in c.fetchall()}
        conn.close()
        
        # Merge data and check for alerts
        for v in volumes:
            parts = v['name'].replace('openvm_vol_', '').split('_', 1)
            v['owner'] = parts[0] if parts else 'unknown'
            v['display_name'] = parts[1] if len(parts) > 1 else v['name']
            v['size_limit_mb'] = limits.get(v['name'])
            
            # Check if over limit
            if v['size_limit_mb'] and v['size_mb'] > v['size_limit_mb']:
                v['over_limit'] = True
                v['usage_percent'] = round((v['size_mb'] / v['size_limit_mb']) * 100, 1)
            else:
                v['over_limit'] = False
                v['usage_percent'] = None
        
        return jsonify({"volumes": volumes})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/volumes/limit', methods=['POST'])
def set_volume_limit():
    """Set or update a volume size limit."""
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    volume_name = data.get('volume_name')
    size_limit_mb = data.get('size_limit_mb')  # None or 0 = no limit
    
    if not volume_name:
        return jsonify({"error": "Volume name required"}), 400
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        if size_limit_mb and size_limit_mb > 0:
            c.execute('''INSERT OR REPLACE INTO volume_limits (volume_name, size_limit_mb) 
                         VALUES (?, ?)''', (volume_name, size_limit_mb))
        else:
            # Remove limit
            c.execute('DELETE FROM volume_limits WHERE volume_name = ?', (volume_name,))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Container Limits API
@app.route('/api/admin/container/limits/<container_id>', methods=['GET'])
def get_container_limits(container_id):
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT limits_enabled, ram_limit_mb, cpu_limit_percent, storage_limit_mb 
                 FROM containers WHERE container_docker_id = ?''', (container_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Container not found"}), 404
    
    return jsonify({
        "limits_enabled": bool(row['limits_enabled']),
        "ram_limit_mb": row['ram_limit_mb'],
        "cpu_limit_percent": row['cpu_limit_percent'],
        "storage_limit_mb": row['storage_limit_mb']
    })

@app.route('/api/admin/container/limits', methods=['POST'])
def set_container_limits():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    container_id = data.get('container_id')
    limits_enabled = data.get('limits_enabled', False)
    ram_limit_mb = data.get('ram_limit_mb')
    cpu_limit_percent = data.get('cpu_limit_percent')
    storage_limit_mb = data.get('storage_limit_mb')  # Informational only
    
    if not container_id:
        return jsonify({"error": "Container ID required"}), 400
    
    try:
        # Update database
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''UPDATE containers SET 
                     limits_enabled = ?, ram_limit_mb = ?, cpu_limit_percent = ?, storage_limit_mb = ?
                     WHERE container_docker_id = ?''',
                  (1 if limits_enabled else 0, ram_limit_mb, cpu_limit_percent, storage_limit_mb, container_id))
        conn.commit()
        conn.close()
        
        # Apply limits to Docker container if enabled
        if limits_enabled:
            DockerHelper.update_container_limits(container_id, ram_mb=ram_limit_mb, cpu_percent=cpu_limit_percent)
        else:
            # Remove limits
            DockerHelper.update_container_limits(container_id, ram_mb=None, cpu_percent=None)
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/container/action', methods=['POST'])
def admin_container_action():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    container_id = data.get('container_id')
    action = data.get('action')
    
    if not container_id or not action:
        return jsonify({"error": "Missing fields"}), 400
        
    try:
        if action == 'start':
            DockerHelper.start(container_id)
        elif action == 'stop':
            DockerHelper.stop(container_id)
        elif action == 'restart':
            DockerHelper.restart(container_id)
        elif action == 'delete':
             DockerHelper.delete_container(container_id)
             # Remove from containers table
             conn = get_db_connection()
             c = conn.cursor()
             c.execute('DELETE FROM containers WHERE container_docker_id = ?', (container_id,))
             conn.commit()
             conn.close()
             return jsonify({"status": "deleted"})
        else:
             return jsonify({"error": "Invalid action"}), 400
             
        # For non-delete actions, return new status
        new_status = DockerHelper.get_status(container_id)
        return jsonify({"status": "success", "new_status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/container/reassign', methods=['POST'])
def reassign_container():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
        
    data = request.json
    container_id = data.get('container_id')
    new_owner = data.get('new_owner')
    
    # Logic:
    # 1. Check if new_owner exists
    # 2. Assign container_id to new_owner
    # 3. Set previous owner's container_id to NULL (implied: container can only belong to one user)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Remove from old owner(s) (actually just update the user_id)
    
    # Get new user ID
    c.execute('SELECT rowid as id FROM users WHERE username = ?', (new_owner,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    new_user_id = row['id']
    
    # Update container record
    c.execute('UPDATE containers SET user_id = ? WHERE container_docker_id = ?', (new_user_id, container_id))
    
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})




@app.route('/settings')
def settings():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('settings.html', username=session['username'], is_admin=session.get('is_admin'), is_blocked=session.get('is_blocked'))

@app.route('/api/settings/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session.get('is_blocked'): return jsonify({"error": "Account blocked"}), 403
        
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    username = session['username']
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    
    if not row or not bcrypt.checkpw(current_password.encode(), row['password_hash'].encode()):
        conn.close()
        return jsonify({"error": "Invalid current password"}), 400
        
    # Update Password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hashed.decode('utf-8'), username))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success"})


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
        
    username = session['username']
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get user block/admin status
    c.execute('SELECT rowid as id, is_admin, is_blocked FROM users WHERE username = ?', (username,))
    user_row = c.fetchone()
    
    if not user_row:
        conn.close()
        return "User not found", 404
        
    user_id = user_row['id']
    is_admin = bool(user_row['is_admin'])
    
    # Get Containers
    c.execute('SELECT container_docker_id, name, status FROM containers WHERE user_id = ?', (user_id,))
    container_rows = c.fetchall()
    conn.close()
    
    containers = []
    for r in container_rows:
        cid = r['container_docker_id']
        try:
            # Refresh status live? Or trust DB? Let's refresh live for now.
            status = DockerHelper.get_status(cid)
        except Exception as e:
            status = "error"
            
        containers.append({
            "id": cid,
            "name": r['name'],
            "status": status
        })
        
    # Handle single container view compatibility or list view
    # If ?target=... is present, use that, else default to first
    target_container_id = request.args.get('target', None)
    
    # Verification: Does target belong to user?
    current_container = None
    if target_container_id:
        for cont in containers:
            if cont['id'] == target_container_id: # Use 'id' alias
                current_container = cont
                break
    
    if not current_container and containers:
        current_container = containers[0]
        
    return render_template('dashboard.html', 
                           username=username, 
                           containers=containers, 
                           current_container=current_container,
                           is_admin=is_admin,
                           is_blocked=bool(user_row['is_blocked']))

@app.route('/api/container/<action>', methods=['POST'])
def container_action(action):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session.get('is_blocked'):
         return jsonify({"error": "Account blocked. Contact admin."}), 403
        
    username = session['username']
    
    # Find container and verify ownership
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT rowid as id FROM users WHERE username = ?', (username,))
    user_row = c.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
        
    # If using specific container from query/post
    target_id = request.json.get('container_id') if request.json else None
    
    # If no target specified, verify default? But logical actions usually specify target now.
    # Let's support target_id in the post body for standard users now.
    
    if target_id:
        c.execute('SELECT container_docker_id FROM containers WHERE user_id = ? AND container_docker_id = ?', (user_row['id'], target_id))
        cont_row = c.fetchone()
        if not cont_row:
             conn.close()
             return jsonify({"error": "Container not found or unauthorized"}), 403
        container_id = target_id
    else:
        # Fallback to first container?
        c.execute('SELECT container_docker_id FROM containers WHERE user_id = ? LIMIT 1', (user_row['id'],))
        cont_row = c.fetchone()
        if not cont_row:
            conn.close()
            return jsonify({"error": "No containers found"}), 404
        container_id = cont_row['container_docker_id']

    conn.close() # Close before docker ops
    
    try:
        if action == 'start':
            DockerHelper.start(container_id)
        elif action == 'stop':
            DockerHelper.stop(container_id)
        elif action == 'restart':
            DockerHelper.restart(container_id)
        else:
            return jsonify({"error": "Invalid action"}), 400
            
        new_status = DockerHelper.get_status(container_id)
        return jsonify({"status": "success", "new_status": new_status})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def verify_container_access(username, container_id):
    conn = get_db_connection()
    c = conn.cursor()
    
    # Check Admin
    c.execute('SELECT is_admin FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    if row and row['is_admin']:
        conn.close()
        return True
        
    # Check User Ownership
    c.execute('''
        SELECT c.container_docker_id 
        FROM containers c 
        JOIN users u ON c.user_id = u.rowid 
        WHERE u.username = ? AND c.container_docker_id = ?
    ''', (username, container_id))
    
    allowed = c.fetchone()
    conn.close()
    return bool(allowed)

# Terminal Logic
# Global storage key: term_id -> TerminalSession
if not hasattr(app, 'terminal_sessions'):
    app.terminal_sessions = {} 
    
# Track sessions being created to prevent race conditions
if not hasattr(app, 'terminal_sessions_creating'):
    app.terminal_sessions_creating = set()

@socketio.on('connect', namespace='/terminal')
def connect_terminal():
    logger.debug(f"Terminal connect: session={session.get('username', 'NONE')}")
    if 'username' not in session:
        logger.warning("Terminal connect rejected: no session")
        return False

@socketio.on('disconnect', namespace='/terminal')
def disconnect_terminal():
    logger.debug("Terminal disconnect")
    pass # Rooms handle cleanup automatically for broadcasting

@socketio.on('start_terminal', namespace='/terminal')
def start_terminal(data):
    logger.info(f"start_terminal called with data keys: {data.keys() if data else 'None'}")
    if 'username' not in session: 
        logger.warning("start_terminal rejected: no session")
        return

    term_id = data.get('term_id')
    logger.debug(f"start_terminal: term_id={term_id}")
    if not term_id:
        emit('output', "Error: No terminal ID provided.\r\n")
        return

    # 1. Existing Session Reconnect
    if term_id in app.terminal_sessions:
        logger.debug(f"Reconnecting to existing session {term_id}")
        join_room(term_id)
        sess = app.terminal_sessions[term_id]
        # Replay history
        for chunk in sess.history:
             emit('output', {"term_id": term_id, "data": chunk}) 
        return
    
    # 1b. Check if session is being created (race condition guard)
    if term_id in app.terminal_sessions_creating:
        logger.warning(f"Session {term_id} is already being created, ignoring duplicate request")
        return
    
    # Mark as creating
    app.terminal_sessions_creating.add(term_id)

    # 2. New Session
    username = session['username']
    if session.get('is_blocked'):
        emit('output', {"term_id": term_id, "data": "Error: Account is blocked.\r\n"})
        return

    # Create session via Manager (Win/Linux handled internally)
    # Warning: pywinpty on Windows requires 'docker' in path.
    # Command is list for Linux, string for Windows? 
    # Actually pywinpty spawn takes string usually, but let's check our implementation.
    # Our adapter takes list for Linux, list for Windows (PtyProcess.spawn handles list?).
    # winpty: "Argument must be a string". Wait. 
    # Let's check terminal_manager implementation again.
    # I'll fix web_app to pass list, and fix manager if needed.
    
    # Actually, let's keep it simple.
    
    cols = data.get('cols', 80)
    rows = data.get('rows', 24)
    target_container = data.get('container_id')
    container_id = None
    
    # Ownership Check (Similar logic to before)
    if session.get('is_admin') and target_container:
        container_id = target_container
    else:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT rowid as id FROM users WHERE username = ?', (username,))
        user_row = c.fetchone()
        
        if not user_row:
             conn.close(); emit('output', {"term_id": term_id, "data": "Error: User not found.\r\n"}); return

        if target_container:
            c.execute('SELECT container_docker_id FROM containers WHERE user_id = ? AND container_docker_id = ?', (user_row['id'], target_container))
            if c.fetchone(): container_id = target_container
        else:
             c.execute('SELECT container_docker_id FROM containers WHERE user_id = ? LIMIT 1', (user_row['id'],))
             row = c.fetchone()
             container_id = row['container_docker_id'] if row else None
        conn.close()

    if not container_id:
        emit('output', {"term_id": term_id, "data": "Error: Container not found or unauthorized.\r\n"})
        return

    # Spawn
    cmd = ['docker', 'exec', '-it', container_id, '/bin/bash']
    if not os.path.exists('/usr/bin/sudo') and not os.name == 'nt':
         # If linux but no sudo? (container mode). 
         # docker_utils logic handles boolean flags, here we hardcoded command.
         pass
         
    import platform
    import shutil
    
    docker_path = shutil.which('docker')
    if not docker_path:
         emit('output', {"term_id": term_id, "data": "Error: Docker executable not found in PATH.\r\n"})
         return

    if platform.system().lower() == 'windows':
        # winpty takes "docker exec -it ..."
        # Use full path to be safe?
        cmd = [docker_path, "exec", "-it", container_id, "/bin/bash"]
        # Convert to string for pywinpty if we want to be safe, but list is usually supported by PtyProcess
        # Actually, let's try joining it to a string if it's Windows, as explicit command line.
        # "C:\Program Files\Docker\docker.exe exec -it ..."
        # We need to quote the path if it has spaces? 
        # PtyProcess should handle list. Let's trust list first but use full path.
    else:
        cmd = ["sudo", docker_path, "exec", "-it", container_id, "/bin/bash"]

    logger.info(f"Creating terminal session for container {container_id}")
    try:
        sess = TerminalManager.create_session(cmd, rows=rows, cols=cols)
        logger.info(f"Terminal session created successfully")
        app.terminal_sessions[term_id] = sess
        join_room(term_id)
        
        # Emit immediately to confirm to client
        emit('output', {"term_id": term_id, "data": ""})
        logger.debug(f"Sent initial empty output to client")
        
        logger.debug(f"Starting background thread for term_id={term_id}")
        import threading
        reader_thread = threading.Thread(target=read_and_forward_pty, args=(term_id,), daemon=True)
        reader_thread.start()
        logger.debug(f"Background thread started")
        
    except Exception as e:
        logger.error(f"Error starting terminal: {e}")
        emit('output', {"term_id": term_id, "data": f"Error starting terminal: {e}\r\n"})
    finally:
        # Clear the creating flag
        if term_id in app.terminal_sessions_creating:
            app.terminal_sessions_creating.discard(term_id)

def read_and_forward_pty(term_id):
    logger.info(f"read_and_forward_pty: starting for term_id={term_id}")
    try:
        loop_count = 0
        while True:
            if term_id not in app.terminal_sessions: 
                logger.debug(f"read_and_forward_pty: term_id {term_id} not in sessions, breaking")
                break
            sess = app.terminal_sessions[term_id]
            
            # Use abstract read
            # Returns: data string (has data), "" (no data yet), None (EOF/error)
            text = sess.read(timeout=0.1)
            loop_count += 1
            
            if loop_count % 100 == 0:
                logger.debug(f"read_and_forward_pty: loop {loop_count}, last read type: {type(text)}")
            
            if text is None:
                # EOF or error
                logger.info(f"read_and_forward_pty: EOF/error for term_id={term_id}")
                socketio.emit('output', {"term_id": term_id, "data": "\r\n[Session Closed]\r\n"}, room=term_id, namespace='/terminal')
                break
            elif text:
                # Has data
                logger.debug(f"read_and_forward_pty: got {len(text)} chars")
                sess.history.append(text)
                if len(sess.history) > 2000: sess.history.pop(0)
                socketio.emit('output', {"term_id": term_id, "data": text}, room=term_id, namespace='/terminal')
            # else: empty string, no data yet, continue loop

            import time
            time.sleep(0.01) 
    except Exception as e:
        logger.error(f"Terminal Output Error: {e}")
    finally:
        logger.info(f"read_and_forward_pty: cleaning up term_id={term_id}")
        if term_id in app.terminal_sessions:
             del app.terminal_sessions[term_id]

@socketio.on('input', namespace='/terminal')
def on_terminal_input(data):
    term_id = data.get('term_id')
    text = data.get('data')
    logger.debug(f"on_terminal_input: term_id={term_id}, text_len={len(text) if text else 0}")
    
    if term_id in app.terminal_sessions:
        sess = app.terminal_sessions[term_id]
        try:
            sess.write(text)
            logger.debug(f"on_terminal_input: wrote successfully")
        except Exception as e:
            logger.error(f"on_terminal_input: write error: {e}")

@socketio.on('resize', namespace='/terminal')
def on_terminal_resize(data):
    term_id = data.get('term_id')
    if term_id in app.terminal_sessions:
        try:
            sess = app.terminal_sessions[term_id]
            cols = data['cols']
            rows = data['rows']
            sess.resize(rows, cols)
        except:
            pass

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
