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


def _run(args):
    """
    Execute a command with safety guards.
    Returns (success: bool, stdout: str).
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
        )
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
    return ok


def is_active():
    """Return True if the fail2ban service is currently active."""
    ok, output = _run(['systemctl', 'is-active', 'fail2ban'])
    return ok and output == 'active'


# ---------------------------------------------------------------------------
# Status & Jails
# ---------------------------------------------------------------------------

def get_status():
    """
    Return overall fail2ban status.
    Returns dict: {active: bool, jails: [str], jail_count: int}
    """
    active = is_active()
    ok, output = _run(['fail2ban-client', 'status'])
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

    ok, output = _run(['fail2ban-client', 'status', jail_name])
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
    ok, output = _run(['fail2ban-client', 'set', jail_name, 'banip', ip_str])
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
    ok, output = _run(['fail2ban-client', 'set', jail_name, 'unbanip', ip_str])
    if ok:
        logger.info('UNBANNED ip=%s jail=%s', ip_str, jail_name)
        return True, f'{ip_str} has been unbanned from {jail_name}.'
    logger.warning('UNBAN FAILED ip=%s jail=%s output=%s', ip_str, jail_name, output)
    return False, output or 'Unban command failed.'


def reload():
    """Reload fail2ban configuration. Returns (success, message)."""
    ok, output = _run(['fail2ban-client', 'reload'])
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
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value):
    """Parse an integer from a string, returning 0 on failure."""
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0
