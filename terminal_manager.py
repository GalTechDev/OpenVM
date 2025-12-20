
import os
import sys
import platform
import struct
import queue
import threading
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('terminal_manager')

# OS Detection
IS_WINDOWS = platform.system().lower() == 'windows'
logger.info(f"OS Detection: IS_WINDOWS={IS_WINDOWS}")

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
        logger.info("pywinpty imported successfully")
    except ImportError as e:
        logger.error(f"pywinpty import failed: {e}")
        PtyProcess = None

    class WindowsTerminalSession(TerminalSession):
        def __init__(self, argv, rows, cols):
            logger.debug(f"WindowsTerminalSession.__init__ called with argv={argv}, rows={rows}, cols={cols}")
            
            if not PtyProcess:
                raise ImportError("pywinpty not installed. Run: pip install pywinpty")
            
            super().__init__(None, None)
            
            logger.debug("Spawning PtyProcess...")
            self.proc = PtyProcess.spawn(argv, dimensions=(rows, cols))
            logger.info(f"PtyProcess spawned successfully")
            
            self._closed = False
            self._output_queue = queue.Queue()
            
            # Start background thread for reading
            logger.debug("Starting reader thread...")
            self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self._reader_thread.start()
            logger.info("Reader thread started")
        
        def _reader_loop(self):
            """Background thread that reads from pywinpty."""
            logger.debug("Reader thread: entering loop")
            try:
                while not self._closed:
                    try:
                        logger.debug("Reader thread: calling proc.read(1024)...")
                        data = self.proc.read(1024)
                        logger.debug(f"Reader thread: read returned {len(data) if data else 0} bytes")
                        if data:
                            self._output_queue.put(data)
                        else:
                            logger.info("Reader thread: EOF detected")
                            self._output_queue.put(None)
                            break
                    except Exception as e:
                        logger.error(f"Reader thread: exception {e}")
                        self._output_queue.put(None)
                        break
            except Exception as e:
                logger.error(f"Reader thread: outer exception {e}")
            logger.debug("Reader thread: exiting")
            
        def read(self, timeout=0.1):
            """Non-blocking read from queue."""
            try:
                data = self._output_queue.get(timeout=timeout)
                logger.debug(f"WindowsTerminalSession.read: got data from queue: {type(data)}")
                return data
            except queue.Empty:
                return ""  # No data yet
        
        def write(self, data):
            logger.debug(f"WindowsTerminalSession.write: writing {len(data)} chars")
            if not self._closed:
                self.proc.write(data)
            
        def resize(self, rows, cols):
            logger.debug(f"WindowsTerminalSession.resize: {rows}x{cols}")
            if not self._closed:
                try:
                    self.proc.setwinsize(rows, cols)
                except Exception as e:
                    logger.error(f"resize error: {e}")
            
        def close(self):
            logger.debug("WindowsTerminalSession.close called")
            self._closed = True
            try:
                self.proc.close()
            except Exception as e:
                logger.error(f"close error: {e}")
            
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
            logger.debug(f"LinuxTerminalSession.__init__ called with cmd={cmd}")
            pid, fd = pty.fork()
            if pid == 0:  # Child
                os.execvp(cmd[0], cmd)
            else:  # Parent
                logger.info(f"LinuxTerminalSession: forked pid={pid}, fd={fd}")
                super().__init__(fd, pid)
                self.resize(rows, cols)
                
        def read(self, timeout=0.1):
            logger.debug(f"LinuxTerminalSession.read: calling select with timeout={timeout}")
            (r, w, x) = select.select([self.fd], [], [], timeout)
            if self.fd in r:
                try:
                    data = os.read(self.fd, 1024)
                    logger.debug(f"LinuxTerminalSession.read: got {len(data)} bytes")
                    if not data:
                        logger.info("LinuxTerminalSession.read: EOF")
                        return None
                    return data.decode('utf-8', errors='ignore')
                except OSError as e:
                    logger.error(f"LinuxTerminalSession.read: OSError {e}")
                    return None
            logger.debug("LinuxTerminalSession.read: timeout, no data")
            return ""
            
        def write(self, data):
            logger.debug(f"LinuxTerminalSession.write: writing {len(data)} chars")
            os.write(self.fd, data.encode())
            
        def resize(self, rows, cols):
            logger.debug(f"LinuxTerminalSession.resize: {rows}x{cols}")
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            
        def close(self):
            logger.debug("LinuxTerminalSession.close called")
            try:
                os.close(self.fd)
            except Exception as e:
                logger.error(f"close error: {e}")

class TerminalManager:
    @staticmethod
    def create_session(cmd, rows=24, cols=80):
        logger.info(f"TerminalManager.create_session: cmd={cmd}, rows={rows}, cols={cols}")
        if IS_WINDOWS:
            return WindowsTerminalSession(cmd, rows, cols)
        else:
            return LinuxTerminalSession(cmd, rows, cols)
