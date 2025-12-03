import socket
import threading
import time
from datetime import datetime
from typing import Optional, Dict
import requests
import json


class HoneypotManager:
    """Manages running honeypot services"""
    _instances: Dict[int, "HoneypotService"] = {}
    _lock = threading.Lock()

    @classmethod
    def get_or_create(cls, hp_id: int, hp_type: str, listen_ip: str, listen_port: int, api_url: str, api_key: str):
        with cls._lock:
            if hp_id in cls._instances:
                return cls._instances[hp_id]
            if hp_type == "ssh":
                instance = SSHHoneypotService(hp_id, listen_ip, listen_port, api_url, api_key)
            elif hp_type == "web":
                instance = WebHoneypotService(hp_id, listen_ip, listen_port, api_url, api_key)
            elif hp_type == "db":
                instance = DatabaseHoneypotService(hp_id, listen_ip, listen_port, api_url, api_key)
            elif hp_type == "smtp":
                instance = SMTPHoneypotService(hp_id, listen_ip, listen_port, api_url, api_key)
            else:
                return None
            cls._instances[hp_id] = instance
            return instance

    @classmethod
    def stop(cls, hp_id: int):
        with cls._lock:
            if hp_id in cls._instances:
                cls._instances[hp_id].stop()
                del cls._instances[hp_id]

    @classmethod
    def is_running(cls, hp_id: int) -> bool:
        with cls._lock:
            return hp_id in cls._instances and cls._instances[hp_id].is_running()


class HoneypotService:
    def __init__(self, hp_id: int, listen_ip: str, listen_port: int, api_url: str, api_key: str):
        self.hp_id = hp_id
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.api_url = api_url
        self.api_key = api_key
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def is_running(self) -> bool:
        return self.running

    def _run(self):
        raise NotImplementedError

    def _submit_event(self, src_ip: str, src_port: int, event_type: str, payload: dict):
        """Submit event to backend API"""
        try:
            requests.post(
                f"{self.api_url}/api/v1/agent/event",
                json={
                    "api_key": self.api_key,
                    "honeypot_id": self.hp_id,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "event_type": event_type,
                    "payload": payload,
                },
                timeout=2,
            )
        except Exception:
            pass  # Silently fail if backend is unavailable


class SSHHoneypotService(HoneypotService):
    def _run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_ip, self.listen_port))
            sock.listen(5)
            sock.settimeout(1.0)

            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    threading.Thread(
                        target=self._handle_ssh_connection,
                        args=(client_sock, addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            response = requests.get(f"{self.api_url}/api/v1/blocked-ips", timeout=1)
            if response.status_code == 200:
                blocked_ips = response.json()
                return any(bip.get("ip") == ip for bip in blocked_ips)
        except Exception:
            pass
        return False

    def _handle_ssh_connection(self, client_sock: socket.socket, addr):
        src_ip, src_port = addr
        
        # Check if IP is blocked
        if self._is_blocked(src_ip):
            try:
                client_sock.close()
            except Exception:
                pass
            return
        
        try:
            # Send fake SSH banner
            client_sock.send(b"SSH-2.0-OpenSSH_7.4p1 Ubuntu-10ubuntu0.3\r\n")
            client_sock.settimeout(30.0)

            # Collect interaction data
            commands = []
            data_buffer = b""

            while self.running:
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    data_buffer += data
                    # Try to extract commands (simplified)
                    if b"\n" in data_buffer:
                        lines = data_buffer.split(b"\n")
                        data_buffer = lines[-1]
                        for line in lines[:-1]:
                            line_str = line.decode("utf-8", errors="ignore").strip()
                            if line_str and len(line_str) < 200:
                                commands.append(line_str)
                except socket.timeout:
                    break
                except Exception:
                    break

            # Submit event
            self._submit_event(
                src_ip,
                src_port,
                "ssh_connection",
                {
                    "port": self.listen_port,
                    "commands": commands,
                    "duration": len(commands),
                    "banner": "SSH-2.0-OpenSSH_7.4p1",
                },
            )
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass


class WebHoneypotService(HoneypotService):
    def _run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_ip, self.listen_port))
            sock.listen(5)
            sock.settimeout(1.0)

            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    threading.Thread(
                        target=self._handle_web_connection,
                        args=(client_sock, addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            response = requests.get(f"{self.api_url}/api/v1/blocked-ips", timeout=1)
            if response.status_code == 200:
                blocked_ips = response.json()
                return any(bip.get("ip") == ip for bip in blocked_ips)
        except Exception:
            pass
        return False

    def _handle_web_connection(self, client_sock: socket.socket, addr):
        src_ip, src_port = addr
        
        # Check if IP is blocked
        if self._is_blocked(src_ip):
            try:
                client_sock.close()
            except Exception:
                pass
            return
        
        try:
            client_sock.settimeout(10.0)
            request_data = client_sock.recv(8192).decode("utf-8", errors="ignore")

            if not request_data:
                # Send minimal response even if no request data
                response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                client_sock.send(response.encode())
                return

            # Parse HTTP request
            lines = request_data.split("\n")
            if not lines:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                client_sock.send(response.encode())
                return

            method_path = lines[0].strip()
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            method = method_path.split()[0] if " " in method_path else "GET"
            path = method_path.split()[1] if " " in method_path else "/"
            user_agent = headers.get("user-agent", "")

            # Template-specific responses based on path patterns
            template_type = "generic"
            if "/.git" in path or "/.git/" in path or "/backup.zip" in path or "/.env" in path or "/config" in path:
                template_type = "git_secrets"
            elif "/sso" in path or "/okta" in path or "/office365" in path or "/microsoft" in path:
                template_type = "sso_portal"
            elif "/router" in path or "/hub" in path or "/iot" in path:
                template_type = "iot_router"
            elif "/wp-" in path or "/phpmyadmin" in path:
                template_type = "cms"
            
            # Generate fake response with more realistic content
            if "/login" in path.lower() or "/admin" in path.lower() or method == "POST":
                # Template-specific login pages
                if template_type == "sso_portal":
                    login_html = """<!DOCTYPE html>
<html><head><title>Single Sign-On</title>
<style>body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px;background:#f5f5f5}
form{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer}
.logo{text-align:center;margin-bottom:20px;font-size:24px;color:#0078d4}</style></head>
<body><div class='logo'>🔐 SSO Portal</div>
<form method='post' action='/login'>
<input type='email' name='email' placeholder='Email address' required>
<input type='password' name='password' placeholder='Password' required>
<button type='submit'>Sign In</button>
</form></body></html>"""
                elif template_type == "iot_router":
                    login_html = """<!DOCTYPE html>
<html><head><title>Router Administration</title>
<style>body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px;background:#f5f5f5}
form{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#4CAF50;color:white;border:none;border-radius:4px;cursor:pointer}
.logo{text-align:center;margin-bottom:20px;font-size:20px}</style></head>
<body><div class='logo'>📡 Router Admin Panel</div>
<form method='post' action='/login'>
<input type='text' name='username' placeholder='Admin Username' required>
<input type='password' name='password' placeholder='Password' required>
<button type='submit'>Login</button>
</form></body></html>"""
                else:
                    login_html = """<!DOCTYPE html>
<html><head><title>Admin Login</title>
<style>body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px;background:#f5f5f5}
form{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#0056b3}</style></head>
<body><h2>Administrator Login</h2>
<form method='post' action='/login'>
<input type='text' name='username' placeholder='Username' required>
<input type='password' name='password' placeholder='Password' required>
<button type='submit'>Sign In</button>
</form></body></html>"""
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(login_html.encode('utf-8'))}\r\nConnection: close\r\n\r\n{login_html}"
            elif "/wp-admin" in path.lower() or "/phpmyadmin" in path.lower():
                forbidden_html = "<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>"
                response = f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(forbidden_html.encode('utf-8'))}\r\nConnection: close\r\n\r\n{forbidden_html}"
            elif template_type == "git_secrets":
                # Git/Secrets honeypot - return fake sensitive files
                if "/.git" in path or path.endswith("/.git"):
                    git_response = "ref: refs/heads/master\n"
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(git_response.encode('utf-8'))}\r\nConnection: close\r\n\r\n{git_response}"
                elif path.endswith(".zip") or "/backup" in path:
                    fake_zip_info = "PK\x03\x04"  # ZIP file header
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {len(fake_zip_info)}\r\nConnection: close\r\n\r\n{fake_zip_info}"
                elif path.endswith(".env") or "/config" in path:
                    fake_config = "DB_PASSWORD=secret123\nAPI_KEY=sk_live_abc123\nSECRET_TOKEN=xyz789"
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(fake_config.encode('utf-8'))}\r\nConnection: close\r\n\r\n{fake_config}"
                else:
                    dir_listing = """<!DOCTYPE html>
<html><head><title>Index of /</title>
<style>body{font-family:monospace;padding:20px;background:#fff}
h1{color:#333}ul{list-style:none;padding:0}
li{padding:5px;border-bottom:1px solid #eee}
a{color:#0066cc;text-decoration:none}
a:hover{text-decoration:underline}</style></head>
<body><h1>Index of /</h1><ul>
<li><a href='.git/'>.git/</a></li>
<li><a href='backup.zip'>backup.zip</a></li>
<li><a href='.env'>.env</a></li>
<li><a href='config.php'>config.php</a></li>
<li><a href='secrets.json'>secrets.json</a></li>
</ul></body></html>"""
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(dir_listing.encode('utf-8'))}\r\nConnection: close\r\n\r\n{dir_listing}"
            else:
                dir_listing = """<!DOCTYPE html>
<html><head><title>Index of /</title>
<style>body{font-family:monospace;padding:20px;background:#fff}
h1{color:#333}ul{list-style:none;padding:0}
li{padding:5px;border-bottom:1px solid #eee}
a{color:#0066cc;text-decoration:none}
a:hover{text-decoration:underline}</style></head>
<body><h1>Index of /</h1><ul>
<li><a href='config.php'>config.php</a></li>
<li><a href='backup.sql'>backup.sql</a></li>
<li><a href='admin/'>admin/</a></li>
<li><a href='.env'>.env</a></li>
</ul></body></html>"""
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(dir_listing.encode('utf-8'))}\r\nConnection: close\r\n\r\n{dir_listing}"

            # Send response in one go
            response_bytes = response.encode('utf-8')
            client_sock.sendall(response_bytes)

            # Extract potential credentials from POST
            payload_data = {}
            if method == "POST" and "\r\n\r\n" in request_data:
                body = request_data.split("\r\n\r\n", 1)[1]
                if "user=" in body or "pass=" in body:
                    for pair in body.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            payload_data[k] = v

            # Submit event with template type
            event_type = "web_request"
            if template_type == "git_secrets":
                event_type = "secrets_hunt"
            elif template_type == "sso_portal":
                event_type = "sso_login_attempt"
            elif template_type == "iot_router":
                event_type = "router_access"
            
            self._submit_event(
                src_ip,
                src_port,
                event_type,
                {
                    "port": self.listen_port,
                    "method": method,
                    "path": path,
                    "user_agent": user_agent,
                    "headers": headers,
                    "payload": payload_data,
                    "template_type": template_type,
                },
            )
        except Exception as e:
            # Try to send error response if possible
            try:
                error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                client_sock.sendall(error_response.encode())
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

