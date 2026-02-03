import socket
from PyQt5.QtCore import QThread, pyqtSignal

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MYSQL",
    3389: "RDP",
}


class ScannerThread(QThread):
    found = pyqtSignal(int, str, str)   # port, status, service
    scanning = pyqtSignal(int)          # current port
    progress = pyqtSignal(int)          # 0..100
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, target: str, start_port: int, end_port: int, timeout: float = 0.5):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            ip = socket.gethostbyname(self.target)
        except Exception as e:
            self.error.emit(f"Target resolve bo‘lmadi: {e}")
            self.finished.emit()
            return

        total = max(1, (self.end_port - self.start_port + 1))
        scanned = 0

        for port in range(self.start_port, self.end_port + 1):
            if self._stop:
                break

            self.scanning.emit(port)
            scanned += 1
            pct = int((scanned / total) * 100)
            self.progress.emit(pct)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                res = sock.connect_ex((ip, port))
                sock.close()

                if res == 0:
                    service = COMMON_SERVICES.get(port, "")
                    self.found.emit(port, "OPEN", service)

            except Exception:
                # scan davom etsin, bitta port xato bo‘lsa ham
                continue

        self.finished.emit()
