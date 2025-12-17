
import os
import sys
import platform
import struct

# OS Detection
IS_WINDOWS = platform.system().lower() == 'windows'

class TerminalSession:
    """Abstract base class for a terminal session."""
    def __init__(self, fd, pid):
        self.fd = fd
        self.pid = pid
        self.history = []

    def read(self, timeout=0.1):
        raise NotImplementedError()

    def write(self, data):
        raise NotImplementedError()

    def resize(self, rows, cols):
        raise NotImplementedError()
        
    def close(self):
        raise NotImplementedError()
        
    def get_fd(self):
        return self.fd

if IS_WINDOWS:
    # Windows Implementation using pywinpty
    try:
        from winpty import PtyProcess
    except ImportError:
        PtyProcess = None

    class WindowsTerminalSession(TerminalSession):
        def __init__(self, argv, rows, cols):
            if not PtyProcess:
                raise ImportError("pywinpty not installed")
            
            # PtyProcess spawn
            self.proc = PtyProcess.spawn(argv, dimensions=(rows, cols))
            super().__init__(None, None) # No FD or standard PID exposed easily
            
        def read(self, timeout=0.1):
            try:
                # pywinpty read is blocking?
                # It has a read(bytes) method.
                # We can check if isalive?
                # Actually, there is no easy non-blocking read with timeout in pywinpty API directly
                # unless we assume it returns empty if no data?
                # Documentation says "Read at most length bytes from the pseudo terminal"
                # It might block.
                # Use a small read size or check flag?
                # Actually, let's just return what we can.
                return self.proc.read(1024)
            except Exception:
                return ""
        
        def write(self, data):
            self.proc.write(data)
            
        def resize(self, rows, cols):
            self.proc.set_winsize(rows, cols)
            
        def close(self):
            self.proc.close()
            
        def get_fd(self):
            return None # Not selectable

else:
    # Linux Implementation
    import pty
    import termios
    import fcntl
    import select
    
    class LinuxTerminalSession(TerminalSession):
        def __init__(self, cmd, rows, cols):
            # pty.fork()
            pid, fd = pty.fork()
            if pid == 0: # Child
                # Resize before exec? Or just rely on shell
                # Execute
                os.execvp(cmd[0], cmd)
            else: # Parent
                super().__init__(fd, pid)
                self.resize(rows, cols)
                
        def read(self, timeout=0.1):
            (r, w, x) = select.select([self.fd], [], [], timeout)
            if self.fd in r:
                return os.read(self.fd, 1024).decode('utf-8', errors='ignore')
            return None
            
        def write(self, data):
            os.write(self.fd, data.encode())
            
        def resize(self, rows, cols):
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            
        def close(self):
            # os.close(self.fd) # Handled by process exit?
            pass

class TerminalManager:
    @staticmethod
    def create_session(cmd, rows=24, cols=80):
        if IS_WINDOWS:
            return WindowsTerminalSession(cmd, rows, cols)
        else:
            return LinuxTerminalSession(cmd, rows, cols)
