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
    Read the last *num_lines* from a whitelisted log file.
    Returns list of strings (lines).
    """
    path = ALLOWED_LOG_PATHS.get(log_key)
    if not path:
        return [f'Unknown log key: {log_key}']

    if not os.path.isfile(path):
        return [f'Log file not found: {path}']

    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
        return [_sanitise(line) for line in lines[-num_lines:]]
    except PermissionError:
        return [f'Permission denied: {path}']
    except Exception as exc:
        return [f'Error reading log: {exc}']


# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------

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
