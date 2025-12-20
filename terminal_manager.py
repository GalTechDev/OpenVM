
import os
import sys
import platform
import struct
import queue
import threading

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
    # Windows Implementation using pywinpty with threaded reader
    try:
        from winpty import PtyProcess
    except ImportError:
        PtyProcess = None

    class WindowsTerminalSession(TerminalSession):
        def __init__(self, argv, rows, cols):
            if not PtyProcess:
                raise ImportError("pywinpty not installed. Run: pip install pywinpty")
            
            super().__init__(None, None)
            
            # PtyProcess spawn
            self.proc = PtyProcess.spawn(argv, dimensions=(rows, cols))
            self._closed = False
            self._output_queue = queue.Queue()
            
            # Start background thread for reading (blocking read won't block gevent)
            self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self._reader_thread.start()
        
        def _reader_loop(self):
            """Background thread that reads from pywinpty and puts data into queue."""
            try:
                while not self._closed:
                    try:
                        data = self.proc.read(1024)
                        if data:
                            self._output_queue.put(data)
                        else:
                            # EOF
                            self._output_queue.put(None)
                            break
                    except Exception:
                        self._output_queue.put(None)
                        break
            except Exception:
                pass
            
        def read(self, timeout=0.1):
            """Non-blocking read from queue."""
            try:
                data = self._output_queue.get(timeout=timeout)
                return data  # Could be string or None (EOF)
            except queue.Empty:
                return ""  # No data yet
        
        def write(self, data):
            if not self._closed:
                self.proc.write(data)
            
        def resize(self, rows, cols):
            if not self._closed:
                try:
                    self.proc.setwinsize(rows, cols)
                except Exception:
                    pass
            
        def close(self):
            self._closed = True
            try:
                self.proc.close()
            except Exception:
                pass
            
        def get_fd(self):
            return None

else:
    # Linux Implementation
    import pty
    import termios
    import fcntl
    import select
    
    class LinuxTerminalSession(TerminalSession):
        def __init__(self, cmd, rows, cols):
            pid, fd = pty.fork()
            if pid == 0:  # Child
                os.execvp(cmd[0], cmd)
            else:  # Parent
                super().__init__(fd, pid)
                self.resize(rows, cols)
                
        def read(self, timeout=0.1):
            (r, w, x) = select.select([self.fd], [], [], timeout)
            if self.fd in r:
                try:
                    data = os.read(self.fd, 1024)
                    if not data:
                        return None  # EOF
                    return data.decode('utf-8', errors='ignore')
                except OSError:
                    return None  # Error/closed
            return ""  # Timeout, no data yet
            
        def write(self, data):
            os.write(self.fd, data.encode())
            
        def resize(self, rows, cols):
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            
        def close(self):
            try:
                os.close(self.fd)
            except Exception:
                pass

class TerminalManager:
    @staticmethod
    def create_session(cmd, rows=24, cols=80):
        if IS_WINDOWS:
            return WindowsTerminalSession(cmd, rows, cols)
        else:
            return LinuxTerminalSession(cmd, rows, cols)
