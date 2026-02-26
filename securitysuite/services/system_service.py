"""
CyberPanel Security Suite — System Service
Utilities for log reading, plugin logging, and system checks.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Whitelisted log paths (read-only access)
# ---------------------------------------------------------------------------

ALLOWED_LOG_PATHS = {
    'fail2ban': '/var/log/fail2ban.log',
    'securitysuite': '/var/log/securitysuite.log',
}

PLUGIN_LOG_PATH = '/var/log/securitysuite.log'


# ---------------------------------------------------------------------------
# Plugin logger setup
# ---------------------------------------------------------------------------

def get_plugin_logger():
    """
    Return a configured logger that writes to /var/log/securitysuite.log.
    Uses a RotatingFileHandler to prevent unbounded growth.
    """
    _logger = logging.getLogger('securitysuite')
    if not _logger.handlers:
        _logger.setLevel(logging.INFO)
        try:
            handler = RotatingFileHandler(
                PLUGIN_LOG_PATH,
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=3,
            )
            formatter = logging.Formatter(
                '[%(asctime)s] %(levelname)s %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )
            handler.setFormatter(formatter)
            _logger.addHandler(handler)
        except PermissionError:
            # Fallback: no file logging if permission denied
            pass
    return _logger


# Initialise on import so all modules can use logging.getLogger('securitysuite')
get_plugin_logger()


# ---------------------------------------------------------------------------
# Log file reader
# ---------------------------------------------------------------------------

def read_log_file(log_key='fail2ban', num_lines=200):
    """
    Read the last *num_lines* from a whitelisted log file securely using sudo.
    Returns list of strings (lines).
    """
    path = ALLOWED_LOG_PATHS.get(log_key)
    if not path:
        return [f'Unknown log key: {log_key}']

    import subprocess
    try:
        # Run sudo tail -n {num_lines} {path}
        # lscpd allows sudo without password for certain commands or ALL if configured properly
        result = subprocess.run(
            ['sudo', 'tail', '-n', str(num_lines), path],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if not lines:
                return [f'Log file is empty: {path}']
            return [_sanitise(line) for line in lines]
        else:
            return [f'Failed to read log {path}', f'Error: {result.stderr.strip()}']
    except Exception as exc:
        return [f'Error reading log: {exc}']


# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------

def get_ban_times(ip_list, max_lines=5000):
    """
    Read the fail2ban log and extract the most recent Ban time for each given IP.
    Returns dict: {'ip': 'YYYY-MM-DD HH:MM:SS'}
    """
    if not ip_list:
        return {}
        
    path = ALLOWED_LOG_PATHS.get('fail2ban')
    if not path:
        return {}

    import subprocess
    
    result_map = {ip: 'Unknown' for ip in ip_list}
    ips_to_find = set(ip_list)
    
    try:
        result = subprocess.run(
            ['sudo', 'tail', '-n', str(max_lines), path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            # Read from bottom to get most recent bans first
            for line in reversed(lines):
                if not ips_to_find:
                    break
                    
                line = _sanitise(line)
                
                # Sample log: 2024-03-24 15:30:12,123 fail2ban.actions [123]: NOTICE [sshd] Ban 192.168.1.100
                if ' Ban ' in line:
                    parts = line.split(' ')
                    # parts[0] is typically date, parts[1] is time (potentially with comma milliseconds)
                    if len(parts) >= 8:
                        date_str = parts[0]
                        time_str = parts[1].split(',')[0]
                        banned_ip = parts[-1]
                        
                        if banned_ip in ips_to_find:
                            # Construct timestamp
                            result_map[banned_ip] = f"{date_str} {time_str}"
                            ips_to_find.remove(banned_ip)
                            
    except Exception as exc:
        get_plugin_logger().error(f"Error fetching ban times: {exc}")
        
    return result_map

def check_service_exists(service_name):
    """
    Return True if a systemd service unit exists.
    Only checks known safe service names.
    """
    import subprocess
    allowed = {'fail2ban', 'lscpd', 'csf', 'lfd'}
    if service_name not in allowed:
        return False
    try:
        result = subprocess.run(
            ['systemctl', 'list-unit-files', f'{service_name}.service'],
            capture_output=True, text=True, timeout=5,
        )
        return service_name in result.stdout
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitise(text):
    """Strip ANSI codes and dangerous characters from log lines."""
    import re
    # Remove ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    # Remove carriage returns
    text = text.replace('\r', '')
    # Strip trailing newline
    return text.rstrip('\n')
