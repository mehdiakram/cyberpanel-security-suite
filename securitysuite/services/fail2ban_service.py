"""
CyberPanel Security Suite — Fail2ban Service
Secure wrapper around fail2ban-client with whitelisted commands only.

Security measures:
  • subprocess.run() with argument list — NO shell=True
  • Strict jail-name validation (alphanumeric, hyphens, underscores, max 64)
  • Strict IP validation via Python ipaddress module
  • 10-second command timeout
  • All output parsed and sanitised before returning
"""

import os
import re
import ipaddress
import subprocess
import logging

logger = logging.getLogger('securitysuite')

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_JAIL_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


def validate_jail_name(name):
    """Return True if *name* is a safe jail identifier."""
    return bool(name and _JAIL_RE.match(name))


def validate_ip(ip_str):
    """Return True if *ip_str* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Command execution (whitelisted only)
# ---------------------------------------------------------------------------

_CMD_TIMEOUT = 10  # seconds

# Auto-detect fail2ban-client path (lscpd may not have it in PATH)
_F2B_CLIENT = None

def _get_f2b_client():
    global _F2B_CLIENT
    if _F2B_CLIENT:
        return _F2B_CLIENT
    # Try common paths
    import shutil
    path = shutil.which('fail2ban-client')
    if path:
        _F2B_CLIENT = path
        return path
    for p in ['/usr/bin/fail2ban-client', '/usr/local/bin/fail2ban-client', '/usr/sbin/fail2ban-client']:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            _F2B_CLIENT = p
            return p
    _F2B_CLIENT = 'fail2ban-client'  # fallback
    return _F2B_CLIENT


def _run(args):
    """
    Execute a command with safety guards.
    Returns (success: bool, stdout: str).
    """
    try:
        # Prepend sudo if not already there, to avoid permission issues with socket
        if args[0] != 'sudo':
            args = ['sudo'] + args
            
        # Ensure common paths are in PATH (lscpd may have limited env)
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:' + env.get('PATH', '')

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
            env=env,
        )
        if result.returncode != 0 and result.stderr:
            logger.warning('Command %s stderr: %s', args[0], result.stderr.strip())
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.error('Command timed out: %s', ' '.join(args))
        return False, 'Command timed out.'
    except FileNotFoundError:
        logger.error('Command not found: %s', args[0])
        return False, f'{args[0]} is not installed.'
    except Exception as exc:
        logger.exception('Unexpected error running command: %s', exc)
        return False, 'Unexpected error.'


# ---------------------------------------------------------------------------
# Service availability
# ---------------------------------------------------------------------------

def is_fail2ban_installed():
    """Check if fail2ban-client binary is available."""
    ok, _ = _run(['which', 'fail2ban-client'])
    if ok:
        return True
    # Also check common paths
    for p in ['/usr/bin/fail2ban-client', '/usr/local/bin/fail2ban-client', '/usr/sbin/fail2ban-client']:
        if os.path.isfile(p):
            return True
    return False


def is_active():
    """Return True if the fail2ban service is currently active."""
    ok, output = _run([_get_f2b_client(), 'ping'])
    return ok and 'pong' in output.lower()


# ---------------------------------------------------------------------------
# Status & Jails
# ---------------------------------------------------------------------------

def get_status():
    """
    Return overall fail2ban status.
    Returns dict: {active: bool, jails: [str], jail_count: int}
    """
    active = is_active()
    ok, output = _run([_get_f2b_client(), 'status'])
    jails = []
    if ok:
        for line in output.splitlines():
            if 'Jail list:' in line:
                raw = line.split(':', 1)[1].strip()
                jails = [j.strip() for j in raw.split(',') if j.strip()]
                break
    return {
        'active': active,
        'jails': jails,
        'jail_count': len(jails),
    }


def get_jail_status(jail_name):
    """
    Return detailed status for a single jail.
    Returns dict with jail info or error.
    """
    if not validate_jail_name(jail_name):
        return {'error': 'Invalid jail name.'}

    ok, output = _run([_get_f2b_client(), 'status', jail_name])
    if not ok:
        return {'error': f'Could not get status for jail: {jail_name}'}

    info = {
        'jail': jail_name,
        'currently_failed': 0,
        'total_failed': 0,
        'currently_banned': 0,
        'total_banned': 0,
        'banned_ips': [],
        'filter': '',
    }

    for line in output.splitlines():
        line = line.strip()
        if 'Currently failed:' in line:
            info['currently_failed'] = _safe_int(line.split(':')[-1])
        elif 'Total failed:' in line:
            info['total_failed'] = _safe_int(line.split(':')[-1])
        elif 'Currently banned:' in line:
            info['currently_banned'] = _safe_int(line.split(':')[-1])
        elif 'Total banned:' in line:
            info['total_banned'] = _safe_int(line.split(':')[-1])
        elif 'Banned IP list:' in line:
            raw = line.split(':', 1)[1].strip()
            info['banned_ips'] = [ip.strip() for ip in raw.split() if ip.strip()]
        elif 'File list:' in line:
            info['filter'] = line.split(':', 1)[1].strip()

    return info


def get_all_banned_ips():
    """
    Return all banned IPs grouped by jail.
    Returns list of dicts: [{jail, banned_ips: [str]}]
    """
    status = get_status()
    result = []
    for jail in status['jails']:
        jail_info = get_jail_status(jail)
        if 'error' not in jail_info:
            result.append({
                'jail': jail,
                'banned_ips': jail_info.get('banned_ips', []),
            })
    return result


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def ban_ip(jail_name, ip_str):
    """Ban an IP in the specified jail. Returns (success, message)."""
    if not validate_jail_name(jail_name):
        return False, 'Invalid jail name.'
    if not validate_ip(ip_str):
        return False, 'Invalid IP address.'

    ip_str = ip_str.strip()
    ok, output = _run([_get_f2b_client(), 'set', jail_name, 'banip', ip_str])
    if ok:
        logger.info('BANNED ip=%s jail=%s', ip_str, jail_name)
        return True, f'{ip_str} has been banned in {jail_name}.'
    logger.warning('BAN FAILED ip=%s jail=%s output=%s', ip_str, jail_name, output)
    return False, output or 'Ban command failed.'


def unban_ip(jail_name, ip_str):
    """Unban an IP from the specified jail. Returns (success, message)."""
    if not validate_jail_name(jail_name):
        return False, 'Invalid jail name.'
    if not validate_ip(ip_str):
        return False, 'Invalid IP address.'

    ip_str = ip_str.strip()
    ok, output = _run([_get_f2b_client(), 'set', jail_name, 'unbanip', ip_str])
    if ok:
        logger.info('UNBANNED ip=%s jail=%s', ip_str, jail_name)
        return True, f'{ip_str} has been unbanned from {jail_name}.'
    logger.warning('UNBAN FAILED ip=%s jail=%s output=%s', ip_str, jail_name, output)
    return False, output or 'Unban command failed.'


def reload():
    """Reload fail2ban configuration. Returns (success, message)."""
    ok, output = _run([_get_f2b_client(), 'reload'])
    if ok:
        logger.info('Fail2ban configuration reloaded.')
        return True, 'Fail2ban reloaded successfully.'
    logger.error('Fail2ban reload failed: %s', output)
    return False, output or 'Reload failed.'


def restart_service():
    """Restart the fail2ban systemd service. Returns (success, message)."""
    ok, output = _run(['systemctl', 'restart', 'fail2ban'])
    if ok:
        logger.info('Fail2ban service restarted.')
        return True, 'Fail2ban restarted successfully.'
    logger.error('Fail2ban restart failed: %s', output)
    return False, output or 'Restart failed.'


# ---------------------------------------------------------------------------
# Whitelist (ignoreip)
# ---------------------------------------------------------------------------

import platform
import sys

if sys.platform == 'win32' or 'laragon' in os.path.abspath(__file__).lower() or os.name == 'nt':
    # Use a dummy local path for Windows / Laragon testing
    JAIL_LOCAL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'jail.local.test')
else:
    JAIL_LOCAL_PATH = '/etc/fail2ban/jail.local'

def _write_jail_local_lines(lines):
    try:
        os.makedirs(os.path.dirname(JAIL_LOCAL_PATH), exist_ok=True)
        with open(JAIL_LOCAL_PATH, 'w') as f:
            f.writelines(lines)
        return True, ''
    except PermissionError:
        import tempfile
        try:
            dir_path = os.path.dirname(JAIL_LOCAL_PATH)
            _run(['mkdir', '-p', dir_path])
            
            with tempfile.NamedTemporaryFile('w', delete=False) as tf:
                tf.writelines(lines)
                tmp_path = tf.name
            
            ok, output = _run(['cp', tmp_path, JAIL_LOCAL_PATH])
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            
            if not ok:
                msg = output if output else 'Permission denied: cannot write to jail.local.'
                return False, f'Failed to write {JAIL_LOCAL_PATH}. {msg}'
            
            _run(['chmod', '644', JAIL_LOCAL_PATH])
            return True, ''
        except Exception as e:
            return False, f'Error writing config: {e}'


def get_whitelist():
    """Return a list of whitelisted IPs from jail.local."""
    if not os.path.isfile(JAIL_LOCAL_PATH):
        return []
    try:
        with open(JAIL_LOCAL_PATH, 'r') as f:
            for line in f:
                if line.strip().startswith('ignoreip'):
                    # ignoreip = 127.0.0.1/8 ::1 103.65.135.193
                    parts = line.split('=', 1)
                    if len(parts) > 1:
                        ips = parts[1].strip().split()
                        return [ip for ip in ips if ip not in ('127.0.0.1/8', '::1') and ip.strip()]
    except Exception as exc:
        logger.error('Failed to read whitelist: %s', exc)
    return []

def add_to_whitelist(ip_str):
    """Add an IP to the ignoreip list in jail.local."""
    if not validate_ip(ip_str):
        return False, 'Invalid IP address.'
        
    current = get_whitelist()
    if ip_str in current:
        return True, 'IP is already whitelisted.'
        
    try:
        # Create jail.local if it doesn't exist
        if not os.path.isfile(JAIL_LOCAL_PATH):
            lines = [f"[DEFAULT]\n", f"ignoreip = 127.0.0.1/8 ::1 {ip_str}\n"]
            ok, msg = _write_jail_local_lines(lines)
            if not ok:
                return False, msg
            logger.info('Created jail.local with whitelist IP: %s', ip_str)
        else:
            with open(JAIL_LOCAL_PATH, 'r') as f:
                lines = f.readlines()
                
            found = False
            for i, line in enumerate(lines):
                if line.strip().startswith('ignoreip'):
                    existing = line.strip()
                    if not existing.endswith(' '):
                        lines[i] = existing + f" {ip_str}\n"
                    else:
                        lines[i] = existing + f"{ip_str}\n"
                    found = True
                    break
                    
            if not found:
                # Add under [DEFAULT] if exists, else at top
                for i, line in enumerate(lines):
                    if line.strip() == '[DEFAULT]':
                        lines.insert(i + 1, f"ignoreip = 127.0.0.1/8 ::1 {ip_str}\n")
                        found = True
                        break
                if not found:
                    lines.insert(0, f"[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 {ip_str}\n")

            ok, msg = _write_jail_local_lines(lines)
            if not ok:
                return False, msg
            
        # Reload fail2ban (non-fatal if it fails)
        try:
            reload()
        except Exception:
            logger.warning('Fail2ban reload failed after whitelist update, but config was saved.')
            
        # Sync iptables ACCEPT rules for country block bypass
        try:
            from securitysuite.services import country_block_service
            country_block_service.sync_firewall_whitelist()
        except Exception:
            pass
        return True, f'{ip_str} has been whitelisted.'
    except Exception as exc:
        logger.exception('Failed to add to whitelist: %s', exc)
        return False, f'Failed to update configuration: {exc}'

def remove_from_whitelist(ip_str):
    """Remove an IP from the ignoreip list in jail.local."""
    if not validate_ip(ip_str):
        return False, 'Invalid IP address.'
        
    try:
        if not os.path.isfile(JAIL_LOCAL_PATH):
            return False, 'jail.local not found.'
            
        with open(JAIL_LOCAL_PATH, 'r') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines):
            if line.strip().startswith('ignoreip'):
                parts = line.split('=', 1)
                if len(parts) > 1:
                    ips = parts[1].strip().split()
                    if ip_str in ips:
                        ips.remove(ip_str)
                        lines[i] = f"{parts[0]}= {' '.join(ips)}\n"
                break
        ok, msg = _write_jail_local_lines(lines)
        if not ok:
            return False, msg
            
        reload()
        # Sync iptables ACCEPT rules for country block bypass
        try:
            from securitysuite.services import country_block_service
            country_block_service.sync_firewall_whitelist()
        except Exception:
            pass
        return True, f'{ip_str} has been removed from whitelist.'
    except Exception as exc:
        logger.exception('Failed to remove from whitelist: %s', exc)
        return False, 'Failed to update configuration.'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value):
    """Parse an integer from a string, returning 0 on failure."""
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0
