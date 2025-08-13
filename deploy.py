import os
import paramiko
import logging
import requests
import json
import socket
import time
import threading

# === LOGGING ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)

INSTALLER_FILENAME = "Dynatrace-OneAgent.sh"
REMOTE_INSTALLER_PATH = "/tmp/oneagent.sh"

# Create a global lock for synchronizing the installer download
download_lock = threading.Lock()

def _normalize_dt_tenant_url(dt_tenant):
    """
    Ensures the Dynatrace tenant URL is properly formatted:
    - Starts with 'https://' (or 'http://' if explicitly given)
    - Has no trailing slash.
    """
    if not dt_tenant.startswith("http://") and not dt_tenant.startswith("https://"):
        dt_tenant = "https://" + dt_tenant
    return dt_tenant.rstrip('/')

def get_local_installer_path():
    return os.path.join(os.getcwd(), INSTALLER_FILENAME)

def download_installer(dt_tenant, dt_api_token):
    """
    Downloads the OneAgent installer, validating its integrity by checking size.
    It uses a lock to ensure only one thread attempts to download at a time.
    """
    dt_tenant = _normalize_dt_tenant_url(dt_tenant)
    url = f"{dt_tenant}/api/v1/deployment/installer/agent/unix/default/latest"
    headers = {"Authorization": f"Api-Token {dt_api_token}"}
    local_path = get_local_installer_path()

    with download_lock:
        # Check for existing file. If it's old or empty, remove it to force a fresh download.
        if os.path.exists(local_path):
            file_mod_time = os.path.getmtime(local_path)
            if (time.time() - file_mod_time) > (24 * 3600):
                log.info(f"Installer at {local_path} is old, re-downloading.")
                os.remove(local_path)
            elif os.path.getsize(local_path) == 0:
                log.info(f"Installer at {local_path} is empty, re-downloading.")
                os.remove(local_path)
            else:
                log.info(f"✅ Installer already exists and is recent at {local_path}")
                return local_path

        log.info(f"📥 Downloading installer from {url}")
        
        try:
            response = requests.get(url, headers=headers, stream=True, timeout=60, verify=False)
            
            if response.status_code != 200:
                log.error(f"❌ Download failed: HTTP {response.status_code}")
                log.error(f"Response: {response.text}")
                raise Exception(f"Installer download failed with status {response.status_code}")
            
            content_type = response.headers.get('content-type', '')
            if 'application/x-sh' not in content_type and 'text/plain' not in content_type:
                log.warning(f"⚠️ Unexpected content type: {content_type}")
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(local_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # Log download progress every 1MB
                        if total_size > 0 and downloaded_size % (1024 * 1024) == 0:
                            progress = (downloaded_size / total_size) * 100
                            log.info(f"📥 Download progress: {progress:.1f}% ({downloaded_size / (1024*1024):.1f}MB)")
            
            if not os.path.exists(local_path):
                raise Exception("File was not created after download")
            
            file_size = os.path.getsize(local_path)
            if file_size == 0:
                raise Exception("Downloaded file is empty")
            
            log.info(f"✅ Installer downloaded successfully. Size: {file_size / (1024*1024):.1f}MB")
            return local_path
            
        except requests.exceptions.Timeout:
            log.error("❌ Download timed out after 60 seconds")
            raise Exception("Download timed out")
        except requests.exceptions.ConnectionError:
            log.error("❌ Connection error during download")
            raise Exception("Connection error during download")
        except requests.exceptions.RequestException as e:
            log.error(f"❌ Request failed: {e}")
            raise Exception(f"Download request failed: {e}")
        except Exception as e:
            log.error(f"❌ Unexpected error during download: {e}")
            raise Exception(f"Download failed: {e}")


def is_agent_running(ssh):
    stdin, stdout, stderr = ssh.exec_command("pgrep -f oneagent")
    output = stdout.read().decode().strip()
    return bool(output)


def is_installer_present_remotely(ssh):
    stdin, stdout, stderr = ssh.exec_command(f"[ -f {REMOTE_INSTALLER_PATH} ] && echo 'YES' || echo 'NO'")
    return stdout.read().decode().strip() == 'YES'


def fetch_host_details(host_ip, dt_tenant, dt_api_token):
    """
    Fetches host details from Dynatrace API.
    NOTE: This function requires a Dynatrace API token with the 'entities.read' scope.
    """
    dt_tenant = _normalize_dt_tenant_url(dt_tenant) # Normalize the tenant URL
    log.info(f"🔍 Fetching Dynatrace host info for {host_ip}...")
    url = f"{dt_tenant}/api/v2/entities?entitySelector=type(HOST),ipAddress({host_ip})&fields=+properties.monitoringMode" # Use normalized URL
    headers = {
        "Authorization": f"Api-Token {dt_api_token}"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        
        if response.status_code != 200:
            log.error(f"❌ API Error: HTTP {response.status_code} - {response.text}")
            return None
        
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            log.error(f"❌ Invalid JSON response: {e}")
            log.error(f"Response content: {response.text[:200]}...")
            return None
        
        if not isinstance(data, dict):
            log.error(f"❌ Unexpected response format: expected dict, got {type(data)}")
            return None
        
        if 'entities' not in data:
            log.error(f"❌ Missing 'entities' key in response: {list(data.keys())}")
            return None
        
        if not isinstance(data['entities'], list):
            log.error(f"❌ 'entities' is not a list: {type(data['entities'])}")
            return None
        
        if not data.get("entities"):
            log.warning(f"⚠️ Host {host_ip} not found in Dynatrace API.")
            return None
        
        host = data["entities"][0]
        
        if not isinstance(host, dict):
            log.error(f"❌ Entity is not a dictionary: {type(host)}")
            return None
        
        entity_id = host.get("entityId", "UNKNOWN")
        hostname = host.get("displayName", "UNKNOWN")
        
        properties = host.get("properties", {})
        if not isinstance(properties, dict):
            log.warning("⚠️ Properties is not a dictionary, using default monitoring mode")
            mode = "UNKNOWN"
        else:
            mode = properties.get("monitoringMode", "UNKNOWN")
        
        log.info(f"🏷️ Hostname: {hostname} | Entity ID: {entity_id} | Mode: {mode}")
        
        if entity_id == "UNKNOWN" or hostname == "UNKNOWN":
            log.warning("⚠️ Some host information is missing or incomplete")
        
        return {"entity_id": entity_id, "hostname": hostname, "monitoring_mode": mode}
        
    except requests.exceptions.Timeout:
        log.error("❌ API request timed out after 30 seconds")
        return None
    except requests.exceptions.ConnectionError:
        log.error("❌ Connection error - check network connectivity")
        return None
    except requests.exceptions.RequestException as e:
        log.error(f"❌ Request failed: {e}")
        return None
    except Exception as e:
        log.error(f"❌ Unexpected error in fetch_host_details: {e}")
        log.error(f"Error type: {type(e).__name__}")
        return None


def onboard_agent(host_ip, username, password, dt_tenant, dt_api_token, mode, host_group="Default"):
    """
    Main function to onboard a single host with the Dynatrace OneAgent.
    Handles downloading, uploading, and installing the agent via SSH.
    """
    local_path = download_installer(dt_tenant, dt_api_token)
    ssh = None

    try:
        log.info(f"🔐 Connecting to {host_ip} via SSH...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(host_ip, username=username, password=password, timeout=30)
        log.info(f"✅ SSH connection established to {host_ip}")

        if is_agent_running(ssh):
            log.info(f"✅ OneAgent is already running on remote host {host_ip}.")
            fetch_host_details(host_ip, dt_tenant, dt_api_token)
            return "Agent already running."

        if not is_installer_present_remotely(ssh):
            log.info(f"📤 Uploading installer to remote server {host_ip}...")
            try:
                sftp = ssh.open_sftp()
                sftp.put(local_path, REMOTE_INSTALLER_PATH)
                sftp.chmod(REMOTE_INSTALLER_PATH, 0o755)
                sftp.close()
                log.info(f"✅ Installer uploaded successfully to {host_ip}")
            except Exception as e:
                log.error(f"❌ Failed to upload installer to {host_ip}: {e}")
                raise Exception(f"SFTP upload failed to {host_ip}: {e}")
        else:
            log.info(f"📝 Installer already present on remote host {host_ip}. Skipping upload.")

        # Decide monitoring mode argument based on input
        mmode = ""
        if mode.lower() == "full" or mode.lower() == "fullstack":
            mmode = "fullstack"
        elif mode.lower() == "infra" or mode.lower() == "infra-only":
            mmode = "infra-only"
        else:
            # Default to fullstack if mode is not recognized
            mmode = "fullstack"
            log.warning(f"⚠️ Unrecognized monitoring mode '{mode}'. Defaulting to 'fullstack'.")

        log.info(f"⚙️ Running installer remotely on {host_ip} in mode: {mmode}...")
        install_cmd = f"echo '{password}' | sudo -S {REMOTE_INSTALLER_PATH} --set-host-group='{host_group}' --set-monitoring-mode={mmode}"
        
        stdin, stdout, stderr = ssh.exec_command(install_cmd, timeout=300)
        
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()

        if exit_code == 0:
            log.info(f"✅ OneAgent installed successfully on {host_ip}.")
            if output.strip():
                log.info(f"Installation output for {host_ip}: {output.strip()}")
            fetch_host_details(host_ip, dt_tenant, dt_api_token)
            return "Installation successful."
        else:
            log.error(f"❌ Installation failed on {host_ip}. Exit code {exit_code}")
            if error.strip():
                log.error(f"Error output for {host_ip}: {error.strip()}")
            if output.strip():
                log.info(f"Standard output for {host_ip}: {output.strip()}")
            raise Exception(f"Installation failed on {host_ip} with exit code {exit_code}")

    except paramiko.AuthenticationException:
        log.error(f"❌ SSH authentication failed for {host_ip} - check username and password")
        raise Exception(f"SSH authentication failed for {host_ip}")
    except paramiko.SSHException as e:
        log.error(f"❌ SSH error for {host_ip}: {e}")
        raise Exception(f"SSH error for {host_ip}: {e}")
    except socket.timeout:
        log.error(f"❌ SSH connection to {host_ip} timed out")
        raise Exception(f"SSH connection to {host_ip} timed out")
    except Exception as e:
        log.error(f"❌ Unexpected error during onboarding for {host_ip}: {e}")
        raise Exception(f"Onboarding failed for {host_ip}: {e}")
    finally:
        if ssh:
            ssh.close()
            log.info(f"🔚 SSH session closed for {host_ip}.")

if __name__ == "__main__":
    log.info("🚀 Starting Dynatrace OneAgent onboarding process (direct script run)...")
    try:
        example_host = os.getenv("HOST", "172.1.16.42")
        example_username = os.getenv("USERNAME", "administrator")
        example_password = os.getenv("PASSWORD", "@pm05ys%2021")
        example_dt_tenant = os.getenv("DT_TENANT", "https://bxg38192.live.dynatrace.com")
        example_dt_api_token = os.getenv("DT_API_TOKEN", "dt0c01.CCKNWVHCQF5ASQL76B56JV3A.XDGXKG4NRQ7PZIAFBC2T3EHQGYAXSRQHGGRHGYJT4RMUA3FY3UZBEBFIY4JEWH73")
        example_host_group = os.getenv("HOST_GROUP", "Python")
        example_mode = os.getenv("MODE", "infra-only")  # Default to infra-only if not set

        onboard_agent(
            host_ip=example_host,
            username=example_username,
            password=example_password,
            dt_tenant=example_dt_tenant,
            dt_api_token=example_dt_api_token,
            host_group=example_host_group,
            mode=example_mode
        )
    except Exception as e:
        log.error(f"❌ Onboarding failed: {str(e)}")