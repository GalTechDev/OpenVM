
import subprocess
import json
import shlex
import os
import platform

# Detect OS
IS_WINDOWS = platform.system().lower() == 'windows'

CONFIG_PATH = 'data/config.json'

def get_config():
    """Load configuration from file."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except:
            pass
    # Default config
    return {
        "docker_mode": "host",  # "host" (with sudo) or "container" (no sudo)
        "use_sudo": not IS_WINDOWS # Default to True on Linux, False on Windows
    }

def save_config(config):
    """Save configuration to file."""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)

class DockerHelper:
    @staticmethod
    def get_docker_base_cmd():
        """Helper to get the base docker command list based on config."""
        config = get_config()
        # On Windows, never use sudo.
        if IS_WINDOWS or config.get("docker_mode") == "container" or not config.get("use_sudo", True):
            return ["docker"]
        else:
            return ["sudo", "docker"]

    @staticmethod
    def run_command(cmd_list):
        full_cmd = DockerHelper.get_docker_base_cmd() + cmd_list
        
        try:
            result = subprocess.run(
                full_cmd, 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Docker command failed: {e.stderr}")

    @staticmethod
    def inspect(container_id):
        try:
            output = DockerHelper.run_command(["inspect", container_id])
            data = json.loads(output)
            if not data:
                return None
            return data[0]
        except:
            return None

    @staticmethod
    def is_running(container_id):
        info = DockerHelper.inspect(container_id)
        if info and info['State']['Running']:
            return True
        return False
        
    @staticmethod
    def get_status(container_id):
        info = DockerHelper.inspect(container_id)
        if info:
            return info['State']['Status']
        return "not_found"

    @staticmethod
    def create_network(network_name):
        try:
            # Check if exists
            if IS_WINDOWS:
                check = subprocess.run(["docker", "network", "inspect", network_name], capture_output=True)
            else:
                base = DockerHelper.get_docker_base_cmd()
                check = subprocess.run(base + ["network", "inspect", network_name], capture_output=True)
                
            if check.returncode != 0:
                DockerHelper.run_command(["network", "create", network_name])
        except:
            pass

    @staticmethod
    def create_container(username, ports=None, network=None, yaml_config=None, logger=None):
        """
        Create a container for the user.
        ports: string like "8080:80,3000:3000"
        logger: function(msg) -> void
        """
        def log(msg):
            if logger: logger(msg)
            print(msg) # Always print to console

        # docker run -d --name openvm_client_<user> -h <user> ubuntu:latest tail -f /dev/null
        # username here is actually the "suffix" or "ref" passed from web_app
        container_name = f"openvm_client_{username}"
        
        # Check if exists
        try:
            log(f"Removing existing container {container_name} if present...")
            DockerHelper.run_command(["rm", "-f", container_name])
        except:
            pass

        # Parse YAML config if provided
        image = "ubuntu:latest"
        environment = []
        volumes = []
        command = ["tail", "-f", "/dev/null"]
        
        if yaml_config:
            try:
                log("Parsing YAML configuration...")
                import yaml
                config = yaml.safe_load(yaml_config)
                if config:
                    if 'image' in config:
                        image = config['image']
                    if 'environment' in config:
                        environment = config['environment'] if isinstance(config['environment'], list) else []
                    if 'volumes' in config:
                        volumes = config['volumes'] if isinstance(config['volumes'], list) else []
                    if 'command' in config:
                        cmd_val = config['command']
                        if isinstance(cmd_val, str):
                            command = cmd_val.split()
                        elif isinstance(cmd_val, list):
                            command = cmd_val
            except Exception as e:
                log(f"YAML parse error: {e}")

        # Ensure image is present
        log(f"Pulling image {image}...")
        try:
             DockerHelper.run_command(["pull", image])
        except Exception as e:
             log(f"Error pulling image (will try to run anyway): {e}")

        cmd = [
            "run", "-d",
            "--name", container_name,
            "--hostname", username
        ]
        
        if network:
            cmd.extend(["--network", network])
            
        if ports:
            # ports format: "80:80,8080:8080" or list
            if isinstance(ports, str):
                port_list = [p.strip() for p in ports.split(',') if p.strip()]
            else:
                port_list = ports
            
            for p in port_list:
                cmd.extend(["-p", p])

        # Add environment variables
        for env in environment:
            cmd.extend(["-e", env])
        
        # Add volumes
        for vol in volumes:
            cmd.extend(["-v", vol])

        cmd.append(image)
        cmd.extend(command)
        
        log(f"Creating container {container_name}...")
        output = DockerHelper.run_command(cmd)
        log(f"Container created: {output[:12]}")
        
        return output.strip() # Returns long ID

    @staticmethod
    def remove_container(container_id):
        DockerHelper.run_command(["rm", "-f", container_id])

    @staticmethod
    def start(container_id):
        DockerHelper.run_command(["start", container_id])

    @staticmethod
    def stop(container_id):
        DockerHelper.run_command(["stop", container_id])
        
    @staticmethod
    def restart(container_id):
        return DockerHelper.run_command(["restart", container_id])

    @staticmethod
    def update_container_limits(container_id, ram_mb=None, cpu_percent=None):
        """
        Update container resource limits using docker update.
        ram_mb: Memory limit in MB (None = unlimited)
        cpu_percent: CPU limit as percentage (None = unlimited)
        """
        cmd = ["update"]
        
        if ram_mb is not None and ram_mb > 0:
            cmd.extend(["--memory", f"{ram_mb}m"])
            # Set memory swap to same as memory to prevent swap
            cmd.extend(["--memory-swap", f"{ram_mb}m"])
        else:
            # Remove memory limit
            cmd.extend(["--memory", "0"])
            cmd.extend(["--memory-swap", "-1"])
        
        if cpu_percent is not None and cpu_percent > 0:
            # Convert percentage to CPU quota
            # 100% = 1 CPU = 100000 microseconds per 100000 period
            cpu_quota = int(cpu_percent * 1000)  # percentage * 1000
            cmd.extend(["--cpu-quota", str(cpu_quota)])
            cmd.extend(["--cpu-period", "100000"])
        else:
            # Remove CPU limit
            cmd.extend(["--cpu-quota", "0"])
        
        cmd.append(container_id)
        return DockerHelper.run_command(cmd)

    @staticmethod
    def get_logs(container_id, tail=100):
        return DockerHelper.run_command(["logs", "--tail", str(tail), container_id])

    @staticmethod
    def delete_container(container_id):
        return DockerHelper.remove_container(container_id)

    @staticmethod
    def get_container_stats(container_id):
        """Get CPU and memory usage for a container."""
        try:
            # Use --no-stream to get single snapshot, format as JSON-like
            output = DockerHelper.run_command([
                "stats", "--no-stream", "--format",
                "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}",
                container_id
            ])
            if not output:
                return {"cpu": "0%", "mem_usage": "0B / 0B", "mem_percent": "0%"}
            
            parts = output.split("|")
            return {
                "cpu": parts[0] if len(parts) > 0 else "0%",
                "mem_usage": parts[1] if len(parts) > 1 else "0B / 0B",
                "mem_percent": parts[2] if len(parts) > 2 else "0%"
            }
        except:
            return {"cpu": "--", "mem_usage": "--", "mem_percent": "--"}

    @staticmethod
    def list_files(container_id, path="/"):
        # Returns list of dicts: {name, type: 'd'|'f', size, permissions}
        # Using ls -la --time-style=+%Y-%m-%d_%H:%M:%S
        try:
            cmd = ["exec", container_id, "ls", "-la", "--time-style=+%Y-%m-%d_%H:%M:%S", path]
            output = DockerHelper.run_command(cmd)
            lines = output.split('\n')
            files = []
            for line in lines[1:]: # Skip 'total X'
                parts = line.split()
                if len(parts) < 6: continue
                
                # permissions links owner group size date time name
                # drwxr-xr-x 1 root root 4096 2023-10-10_10:10:10 .
                perms = parts[0]
                # links = parts[1]
                # owner = parts[2]
                # group = parts[3]
                size = parts[4]
                date = parts[5]
                name = " ".join(parts[6:])
                
                if name == '.' or name == '..': continue
                
                is_dir = perms.startswith('d')
                files.append({
                    "name": name,
                    "type": "dir" if is_dir else "file",
                    "size": size,
                    "date": date,
                    "perms": perms
                })
            # Sort: Directories first, then files
            return sorted(files, key=lambda x: (x['type'] != 'dir', x['name']))
        except Exception as e:
            print(f"List files error: {e}")
            return []

    @staticmethod
    def put_file(container_id, source_path, dest_path):
        # docker cp source_path container_id:dest_path
        return DockerHelper.run_command(["cp", source_path, f"{container_id}:{dest_path}"])

    @staticmethod
    def get_file_content_cmd(container_id, file_path):
        # For small text files to preview? 
        return ["exec", container_id, "cat", file_path]

    @staticmethod
    def read_file_bytes(container_id, file_path):
        if IS_WINDOWS:
            cmd = ["docker", "exec", container_id, "cat", file_path]
        else:
            cmd = DockerHelper.get_docker_base_cmd() + ["exec", container_id, "cat", file_path]
        result = subprocess.run(cmd, capture_output=True, check=True)
        return result.stdout

    @staticmethod
    def create_directory(container_id, path):
        # mkdir -p path
        DockerHelper.run_command(["exec", container_id, "mkdir", "-p", path])

    @staticmethod
    def rename_path(container_id, old_path, new_path):
        # mv old_path new_path
        DockerHelper.run_command(["exec", container_id, "mv", old_path, new_path])

    @staticmethod
    def delete_path(container_id, path):
        # rm -rf path
        DockerHelper.run_command(["exec", container_id, "rm", "-rf", path])
    
    @staticmethod
    def get_archive_cmd(container_id, path):
        # Returns command to get a tar stream of the path.
        # "docker cp container:path -" dumps tar to stdout
        if IS_WINDOWS:
            return ["docker", "cp", f"{container_id}:{path}", "-"]
        else:
            return DockerHelper.get_docker_base_cmd() + ["cp", f"{container_id}:{path}", "-"]

    # Volume Management
    @staticmethod
    def create_volume(volume_name):
        """Create a Docker volume."""
        return DockerHelper.run_command(["volume", "create", volume_name])

    @staticmethod
    def list_volumes(prefix=None):
        """List Docker volumes, optionally filtered by prefix."""
        output = DockerHelper.run_command([
            "volume", "ls", "--format", "{{.Name}}|{{.Driver}}|{{.Mountpoint}}"
        ])
        volumes = []
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split('|')
            name = parts[0] if len(parts) > 0 else ''
            if prefix and not name.startswith(prefix):
                continue
            volumes.append({
                'name': name,
                'driver': parts[1] if len(parts) > 1 else 'local',
                'mountpoint': parts[2] if len(parts) > 2 else ''
            })
        return volumes

    @staticmethod
    def delete_volume(volume_name):
        """Delete a Docker volume."""
        return DockerHelper.run_command(["volume", "rm", volume_name])

    @staticmethod
    def inspect_volume(volume_name):
        """Get volume details."""
        try:
            import json
            output = DockerHelper.run_command(["volume", "inspect", volume_name])
            data = json.loads(output)
            return data[0] if data else None
        except:
            return None

    @staticmethod
    def get_volume_size(volume_name):
        """Get volume size in MB using a temporary container."""
        try:
            # Use alpine to check size. Works on Linux, Windows, Mac.
            # docker run --rm -v volume:/data alpine du -sk /data
            cmd = [
                "run", "--rm", 
                "-v", f"{volume_name}:/data", 
                "alpine", 
                "du", "-sk", "/data"
            ]
            
            output = DockerHelper.run_command(cmd)
            # Output format: "size_kb    /data"
            if output:
                size_kb = int(output.split()[0])
                return size_kb / 1024 # Convert to MB
            return 0
        except Exception as e:
            # print(f"Error getting volume size: {e}") 
            return 0

    @staticmethod
    def get_all_volumes_with_sizes(prefix="openvm_vol_"):
        """Get all volumes with their sizes."""
        volumes = DockerHelper.list_volumes(prefix=prefix)
        for v in volumes:
            v['size_mb'] = round(DockerHelper.get_volume_size(v['name']), 2)
        return volumes


    @staticmethod
    def attach_volume(container_id, volume_name, mount_path):
        """
        Recreates a container with a new volume attached.
        Returns the new container ID.
        """
        # 1. Inspect existing container
        info = DockerHelper.inspect(container_id)
        if not info:
            raise Exception("Container not found")
            
        # 2. Extract configuration
        # Name: /openvm_client_{suffix}
        name = info['Name']
        if name.startswith('/'): name = name[1:]
        
        if not name.startswith('openvm_client_'):
             raise Exception("Invalid container naming, cannot recreate safely")
             
        username_suffix = name.replace('openvm_client_', '')
        
        # Config
        config = info['Config']
        host_config = info['HostConfig']
        network_settings = info['NetworkSettings']
        
        image = config['Image']
        env = config.get('Env', [])
        cmd = config.get('Cmd', [])
        
        # Ports
        # PortBindings: {'80/tcp': [{'HostIp': '', 'HostPort': '8080'}]}
        ports = []
        if host_config.get('PortBindings'):
            for container_port, host_bindings in host_config['PortBindings'].items():
                c_port = container_port.split('/')[0] # '80'
                if host_bindings:
                    for bind in host_bindings:
                        h_port = bind.get('HostPort')
                        if h_port:
                            ports.append(f"{h_port}:{c_port}")
                    
        # Network
        networks = network_settings.get('Networks', {})
        network_name = list(networks.keys())[0] if networks else None
        
        # Existing Mounts (Volumes/Binds)
        # We need to preserve them.
        # "Mounts": [{"Type": "volume", "Name": "...", "Destination": "..."}]
        volumes_args = []
        if info.get('Mounts'):
            for mount in info['Mounts']:
                 # We only care about user defined volumes or binds?
                 # Docker inspect Mounts includes everything.
                 # Let's reconstruct -v flags.
                 src = mount.get('Name') or mount.get('Source')
                 dst = mount['Destination']
                 volumes_args.append(f"{src}:{dst}")
        
        # Add NEW volume
        new_vol_arg = f"{volume_name}:{mount_path}"
        if new_vol_arg not in volumes_args:
            volumes_args.append(new_vol_arg)
            
        # 3. Recreate
        # We assume create_container logic is too high level (it defaults image/cmd).
        # So we build the command manually here to match `docker run`.
        
        # Cleanup old
        DockerHelper.remove_container(container_id)
        
        # Build Run Command
        
        # Check config for sudo/host mode
        from docker_utils import get_config, IS_WINDOWS
        
        docker_cmd = DockerHelper.get_docker_base_cmd()
            
        run_cmd = docker_cmd + [
            "run", "-d",
            "--name", name,
            "--hostname", config.get('Hostname', username_suffix)
        ]
        
        if network_name:
            run_cmd.extend(["--network", network_name])
            
        for p in ports:
            run_cmd.extend(["-p", p])
            
        for e in env:
            run_cmd.extend(["-e", e])
            
        for v in volumes_args:
            run_cmd.extend(["-v", v])
            
        run_cmd.append(image)
        
        # Append Command if it exists and isn't null
        if cmd:
            run_cmd.extend(cmd)
            
        try:
            result = subprocess.run(
                run_cmd, 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Docker command failed: {e.stderr}")

    @staticmethod
    def detach_volume(container_id, volume_name):
        """
        Recreates a container with the specified volume REMOVED.
        Returns the new container ID.
        """
        # 1. Inspect
        info = DockerHelper.inspect(container_id)
        if not info: raise Exception("Container not found")

        # 2. Extract configuration
        name = info['Name']
        if name.startswith('/'): name = name[1:]
        if not name.startswith('openvm_client_'): raise Exception("Invalid container naming")
        username_suffix = name.replace('openvm_client_', '')

        config = info['Config']
        host_config = info['HostConfig']
        network_settings = info['NetworkSettings']

        image = config['Image']
        env = config.get('Env', [])
        cmd = config.get('Cmd', [])

        # Ports
        ports = []
        if host_config.get('PortBindings'):
             for c_port, bindings in host_config['PortBindings'].items():
                 c_port = c_port.split('/')[0]
                 if bindings:
                     for b in bindings:
                         if 'HostPort' in b: ports.append(f"{b['HostPort']}:{c_port}")

        # Networks
        networks = network_settings.get('Networks', {})
        network_name = list(networks.keys())[0] if networks else None

        # Mounts - Filter out
        volumes_args = []
        if info.get('Mounts'):
            for mount in info['Mounts']:
                 src = mount.get('Name') or mount.get('Source')
                 dst = mount['Destination']
                 
                 # Check strict equality on name or source
                 if src == volume_name:
                     continue
                 
                 volumes_args.append(f"{src}:{dst}")

        # 3. Recreate
        DockerHelper.remove_container(container_id)

        from docker_utils import get_config, IS_WINDOWS
        # Use common helper for base command
        docker_cmd = DockerHelper.get_docker_base_cmd()
        
        run_cmd = docker_cmd + [
            "run", "-d",
            "--name", name,
            "--hostname", config.get('Hostname', username_suffix)
        ]

        if network_name: run_cmd.extend(["--network", network_name])
        for p in ports: run_cmd.extend(["-p", p])
        for e in env: run_cmd.extend(["-e", e])
        for v in volumes_args: run_cmd.extend(["-v", v])
        
        run_cmd.append(image)
        if cmd: run_cmd.extend(cmd)

        try:
            result = subprocess.run(run_cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Docker command failed: {e.stderr}")

    @staticmethod
    def execute_scripts(container_id, scripts, logger=None):
        """
        Execute a list of scripts in the container.
        scripts: list of dicts {'name': str, 'content': str}
        """
        def log(msg):
            if logger: logger(msg)
            print(msg) 

        import time
        
        # Wait for container to be running
        log("Waiting for container startup...")
        max_retries = 30
        for _ in range(max_retries):
            if DockerHelper.is_running(container_id):
                break
            time.sleep(1)
            
        if not DockerHelper.is_running(container_id):
            log(f"Container {container_id} failed to start, skipping scripts")
            return

        for script in scripts:
            name = script['name']
            content = script['content']
            safe_name = "".join(x for x in name if x.isalnum() or x in "._-")
            if not safe_name: safe_name = "script"
            
            log(f"Preparing script: {name}")
            
            # 1. Write to local temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                content = content.replace('\r\n', '\n')
                f.write(content)
                temp_path = f.name
                
            try:
                # 2. Copy to container
                dest_path = f"/tmp/{safe_name}"
                DockerHelper.put_file(container_id, temp_path, dest_path)
                
                # 3. Make executable
                DockerHelper.run_command(["exec", container_id, "chmod", "+x", dest_path])
                
                # Execute
                log(f"Executing {name}...")
                
                res = subprocess.run(
                    DockerHelper.get_docker_base_cmd() + ["exec", container_id, dest_path],
                    capture_output=True, text=True
                )
                
                if res.returncode != 0:
                    log(f"Script {name} failed:\n{res.stderr}")
                else:
                    output = res.stdout.strip()
                    if output:
                        log(f"[{name}] Output:\n{output}")
                    else:
                        log(f"[{name}] Completed (no output)")
                    
            except Exception as e:
                log(f"Error running script {name}: {e}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
