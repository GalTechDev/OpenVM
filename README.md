# 🖥️ OpenVM

**OpenVM** is a lightweight, web-based Docker container manager that provides users with isolated virtual environments accessible via a web terminal.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-SocketIO-green.svg)
![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- 🔐 **User Management** - Admin dashboard for creating/managing users
- 🐳 **Docker Containers** - Each user gets isolated Docker containers
- 💻 **Web Terminal** - Full PTY terminal access via browser (WebSocket)
- 📁 **File Explorer** - Browse, upload, download, rename, delete files in containers
- 📊 **Resource Monitoring** - Real-time CPU, RAM, disk usage stats
- ⚙️ **Container Limits** - Set RAM/CPU limits per container
- 📦 **Volume Management** - Persistent storage with size limits
- 🔒 **User Blocking** - Admins can block/unblock users

## 🚀 Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/GalTechDev/OpenVM.git
cd OpenVM

# Start with Docker Compose
docker-compose up -d
```

Then open http://localhost:5000 and complete the setup wizard.

### Using Docker

```bash
docker run -d \
  --name openvm \
  -p 5000:5000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v openvm_data:/app/data \
  --privileged \
  galteck/openvm:latest
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/GalTechDev/OpenVM.git
cd OpenVM

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python web_app.py
```

## 📋 Requirements

- Python 3.11+
- Docker (installed and running)
- Docker socket access (`/var/run/docker.sock`)

## 🛠️ Configuration

On first launch, OpenVM will:
1. Initialize the SQLite database
2. Display a setup page to create the first admin account
3. Detect Docker configuration (host mode or socket)

## 📁 Project Structure

```
OpenVM/
├── web_app.py          # Main Flask application
├── docker_utils.py     # Docker CLI wrapper
├── manager.py          # CLI user management tool
├── server.py           # SSH server (optional)
├── templates/          # HTML templates
│   ├── login.html
│   ├── dashboard.html
│   ├── admin.html
│   ├── settings.html
│   └── setup.html
├── static/
│   ├── css/style.css
│   └── js/
│       ├── terminal.js
│       └── file_explorer.js
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 🔧 API Endpoints

### Admin Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin` | Admin dashboard |
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/create_user` | Create new user |
| POST | `/api/admin/delete_user` | Delete user |
| POST | `/api/admin/container/create` | Create container |
| POST | `/api/admin/container/action` | Start/stop/restart container |
| GET | `/api/admin/system_stats` | System resource stats |

### User Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | User dashboard |
| POST | `/api/container/<action>` | Container actions |
| POST | `/api/container/files` | List files |
| POST | `/api/container/upload` | Upload file |
| GET | `/api/container/download` | Download file |

### WebSocket
| Namespace | Events | Description |
|-----------|--------|-------------|
| `/terminal` | connect, input, resize, output | Terminal PTY connection |

## 🔒 Security Notes

- Change the `app.secret_key` in production!
- Use HTTPS in production (via reverse proxy)
- Docker socket access grants significant privileges
- Consider using Docker socket proxy for added security

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.
