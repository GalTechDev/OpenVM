
import asyncio
import asyncssh
import sqlite3
import bcrypt
import sys
import os
from docker_utils import DockerHelper

DB_PATH = 'data/db.sqlite'
PORT = 2222

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        print('Connection received from %s' % conn.get_extra_info('peername')[0])

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT password_hash, container_id FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            conn.close()

            if row and bcrypt.checkpw(password.encode(), row['password_hash'].encode()):
                self._username = username
                self._container_id = row['container_id']
                return True
        except Exception as e:
            print(f"Auth error: {e}")
        return False

    def session_requested(self):
        return MySSHServerSession(self._username, self._container_id)

class MySSHServerSession(asyncssh.SSHServerSession):
    def __init__(self, username, container_id):
        self._username = username
        self._container_id = container_id
        self._chan = None
        self._process = None

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        return True

    def pty_requested(self, term_type, term_size, term_modes):
        return True 

    async def session_started(self):
        # 1. Start Container if needed
        try:
            if not DockerHelper.is_running(self._container_id):
                self._chan.write("Container stopped. Starting...\r\n")
                DockerHelper.start(self._container_id)
        except Exception as e:
            self._chan.write(f"Error accessing container: {e}\r\n")
            self._chan.exit(1)
            return

        # 2. Prepare Command
        # We use -it always if the client requested a PTY?
        # IMPORTANT: 'sudo docker exec ...'
        flags = "-i"
        if self._chan.get_terminal_type():
            flags = "-it"
        
        # Check OS for sudo usage
        import platform
        if platform.system().lower() == 'windows':
            docker_cmd = ["docker", "exec", flags, self._container_id, "/bin/bash"]
        else:
            docker_cmd = ["sudo", "docker", "exec", flags, self._container_id, "/bin/bash"]
        
        try:
            self._process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 3. Pump Output
            await asyncio.gather(
                self._pump_stream(self._process.stdout, self._chan.write),
                self._pump_stream(self._process.stderr, self._chan.write_stderr),
                self._pump_input(self._process.stdin) # Need to implement separate pump?
                # Actually, asyncssh pushes data via data_received.
                # We do NOT need to pump input here.
            )
            
            await self._process.wait()
            self._chan.exit(self._process.returncode)
            
        except Exception as e:
            self._chan.write_stderr(f"Error executing docker command: {e}\r\n")
            self._chan.exit(1)

    # ... (same as before)
    async def _pump_stream(self, stream, write_func):
        try:
            while True:
                data = await stream.read(1024)
                if not data:
                    break
                write_func(data)
        except Exception:
            pass

    def data_received(self, data, datatype):
        if self._process and self._process.stdin:
            try:
                self._process.stdin.write(data)
                # Draining? Not async here. Just write.
            except Exception:
                pass

    def eof_received(self):
        if self._process and self._process.stdin:
            try:
                self._process.stdin.write_eof()
            except:
                pass
                
    # To fix 'draining' issue in data_received (which is sync), we rely on default buffer.

async def start_server():
    await asyncssh.listen(
        '', PORT,
        server_factory=MySSHServer,
        server_host_keys=['ssh_host_key']
    )
    print(f"Listening on port {PORT}...")

if __name__ == '__main__':
    if not os.path.exists('ssh_host_key'):
        print("Generating host key...")
        key = asyncssh.generate_private_key('ssh-rsa')
        with open('ssh_host_key', 'w') as f:
            f.write(key.export_private_key().decode())

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server())
    except (OSError, asyncssh.Error) as exc:
        sys.exit('Error starting server: ' + str(exc))

    loop.run_forever()
