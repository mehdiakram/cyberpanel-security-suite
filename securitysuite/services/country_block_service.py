"""
CyberPanel Security Suite — Country Block Service
Block/unblock entire countries using ipset + iptables.
Downloads country CIDR lists from ipdeny.com.
"""

import os
import json
import logging
import subprocess
import threading

logger = logging.getLogger('securitysuite')

_CMD_TIMEOUT = 30
_PERSIST_FILE = '/etc/fail2ban/securitysuite_blocked_countries.json'
_CIDR_CACHE_DIR = '/tmp/securitysuite_cidrs'
_IPSET_PREFIX = 'ss_block_'
_lock = threading.Lock()

# Full country list for UI
COUNTRY_LIST = [
    ("AF", "Afghanistan"), ("AL", "Albania"), ("DZ", "Algeria"), ("AD", "Andorra"),
    ("AO", "Angola"), ("AR", "Argentina"), ("AM", "Armenia"), ("AU", "Australia"),
    ("AT", "Austria"), ("AZ", "Azerbaijan"), ("BH", "Bahrain"), ("BD", "Bangladesh"),
    ("BY", "Belarus"), ("BE", "Belgium"), ("BJ", "Benin"), ("BT", "Bhutan"),
    ("BO", "Bolivia"), ("BA", "Bosnia and Herzegovina"), ("BW", "Botswana"),
    ("BR", "Brazil"), ("BN", "Brunei"), ("BG", "Bulgaria"), ("BF", "Burkina Faso"),
    ("KH", "Cambodia"), ("CM", "Cameroon"), ("CA", "Canada"), ("CF", "Central African Republic"),
    ("CL", "Chile"), ("CN", "China"), ("CO", "Colombia"), ("CD", "Congo (DRC)"),
    ("CR", "Costa Rica"), ("HR", "Croatia"), ("CU", "Cuba"), ("CY", "Cyprus"),
    ("CZ", "Czech Republic"), ("DK", "Denmark"), ("DO", "Dominican Republic"),
    ("EC", "Ecuador"), ("EG", "Egypt"), ("SV", "El Salvador"), ("EE", "Estonia"),
    ("ET", "Ethiopia"), ("FI", "Finland"), ("FR", "France"), ("GE", "Georgia"),
    ("DE", "Germany"), ("GH", "Ghana"), ("GR", "Greece"), ("GT", "Guatemala"),
    ("HN", "Honduras"), ("HK", "Hong Kong"), ("HU", "Hungary"), ("IS", "Iceland"),
    ("IN", "India"), ("ID", "Indonesia"), ("IR", "Iran"), ("IQ", "Iraq"),
    ("IE", "Ireland"), ("IL", "Israel"), ("IT", "Italy"), ("JM", "Jamaica"),
    ("JP", "Japan"), ("JO", "Jordan"), ("KZ", "Kazakhstan"), ("KE", "Kenya"),
    ("KP", "North Korea"), ("KR", "South Korea"), ("KW", "Kuwait"), ("KG", "Kyrgyzstan"),
    ("LA", "Laos"), ("LV", "Latvia"), ("LB", "Lebanon"), ("LY", "Libya"),
    ("LT", "Lithuania"), ("LU", "Luxembourg"), ("MO", "Macau"), ("MK", "North Macedonia"),
    ("MG", "Madagascar"), ("MY", "Malaysia"), ("MV", "Maldives"), ("ML", "Mali"),
    ("MX", "Mexico"), ("MD", "Moldova"), ("MN", "Mongolia"), ("ME", "Montenegro"),
    ("MA", "Morocco"), ("MZ", "Mozambique"), ("MM", "Myanmar"), ("NA", "Namibia"),
    ("NP", "Nepal"), ("NL", "Netherlands"), ("NZ", "New Zealand"), ("NI", "Nicaragua"),
    ("NG", "Nigeria"), ("NO", "Norway"), ("OM", "Oman"), ("PK", "Pakistan"),
    ("PS", "Palestine"), ("PA", "Panama"), ("PY", "Paraguay"), ("PE", "Peru"),
    ("PH", "Philippines"), ("PL", "Poland"), ("PT", "Portugal"), ("QA", "Qatar"),
    ("RO", "Romania"), ("RU", "Russia"), ("RW", "Rwanda"), ("SA", "Saudi Arabia"),
    ("SN", "Senegal"), ("RS", "Serbia"), ("SG", "Singapore"), ("SK", "Slovakia"),
    ("SI", "Slovenia"), ("SO", "Somalia"), ("ZA", "South Africa"), ("ES", "Spain"),
    ("LK", "Sri Lanka"), ("SD", "Sudan"), ("SE", "Sweden"), ("CH", "Switzerland"),
    ("SY", "Syria"), ("TW", "Taiwan"), ("TJ", "Tajikistan"), ("TZ", "Tanzania"),
    ("TH", "Thailand"), ("TG", "Togo"), ("TN", "Tunisia"), ("TR", "Turkey"),
    ("TM", "Turkmenistan"), ("UG", "Uganda"), ("UA", "Ukraine"),
    ("AE", "United Arab Emirates"), ("GB", "United Kingdom"), ("US", "United States"),
    ("UY", "Uruguay"), ("UZ", "Uzbekistan"), ("VE", "Venezuela"), ("VN", "Vietnam"),
    ("YE", "Yemen"), ("ZM", "Zambia"), ("ZW", "Zimbabwe"),
]


def _run(args, timeout=_CMD_TIMEOUT):
    """Execute command safely."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, 'Command timed out.'
    except FileNotFoundError:
        return False, f'{args[0]} not found. Install it first.'
    except Exception as exc:
        return False, str(exc)


def is_ipset_available():
    """Check if ipset is installed."""
    ok, _ = _run(['which', 'ipset'])
    return ok


def get_blocked_countries():
    """Return list of currently blocked country codes."""
    try:
        if os.path.exists(_PERSIST_FILE):
            with open(_PERSIST_FILE, 'r') as f:
                data = json.load(f)
                return data.get('blocked', [])
    except Exception as exc:
        logger.warning('Error reading blocked countries: %s', exc)
    return []


def _save_blocked(countries):
    """Persist blocked country list."""
    try:
        os.makedirs(os.path.dirname(_PERSIST_FILE), exist_ok=True)
        with open(_PERSIST_FILE, 'w') as f:
            json.dump({'blocked': countries}, f)
    except Exception as exc:
        logger.error('Error saving blocked countries: %s', exc)


def _download_cidr(country_code):
    """Download CIDR list for a country from ipdeny.com."""
    try:
        from urllib.request import urlopen as ul_open
    except ImportError:
        from urllib2 import urlopen as ul_open

    code = country_code.lower()
    os.makedirs(_CIDR_CACHE_DIR, exist_ok=True)
    filepath = os.path.join(_CIDR_CACHE_DIR, f'{code}.zone')

    url = f'https://www.ipdeny.com/ipblocks/data/aggregated/{code}-aggregated.zone'
    try:
        resp = ul_open(url, timeout=15)
        data = resp.read()
        with open(filepath, 'wb') as f:
            f.write(data)
        lines = [l.strip() for l in data.decode('utf-8').splitlines() if l.strip() and not l.startswith('#')]
        logger.info('Downloaded %d CIDRs for %s', len(lines), code.upper())
        return lines
    except Exception as exc:
        logger.error('Failed to download CIDRs for %s: %s', code.upper(), exc)
        return []


def block_country(country_code):
    """
    Block all traffic from a country.
    Returns (success: bool, message: str).
    """
    code = country_code.upper().strip()
    if len(code) != 2 or not code.isalpha():
        return False, 'Invalid country code.'

    if not is_ipset_available():
        return False, 'ipset is not installed. Run: apt install ipset -y'

    with _lock:
        blocked = get_blocked_countries()
        if code in blocked:
            return False, f'{code} is already blocked.'

        # Download CIDR list
        cidrs = _download_cidr(code)
        if not cidrs:
            return False, f'Could not download IP ranges for {code}.'

        setname = _IPSET_PREFIX + code.lower()

        # Create ipset
        _run(['ipset', 'destroy', setname])  # remove if leftover
        ok, msg = _run(['ipset', 'create', setname, 'hash:net', 'maxelem', '131072'])
        if not ok:
            return False, f'Failed to create ipset: {msg}'

        # Add CIDRs to ipset
        added = 0
        for cidr in cidrs:
            ok2, _ = _run(['ipset', 'add', setname, cidr, '-exist'])
            if ok2:
                added += 1

        # Add iptables rule
        ok, msg = _run(['iptables', '-I', 'INPUT', '-m', 'set', '--match-set', setname, 'src', '-j', 'DROP'])
        if not ok:
            _run(['ipset', 'destroy', setname])
            return False, f'Failed to add iptables rule: {msg}'

        # Persist
        blocked.append(code)
        _save_blocked(blocked)

        country_name = dict(COUNTRY_LIST).get(code, code)
        logger.info('BLOCKED country=%s (%s) cidrs=%d', code, country_name, added)
        return True, f'{country_name} ({code}) blocked — {added} IP ranges.'


def unblock_country(country_code):
    """
    Remove block for a country.
    Returns (success: bool, message: str).
    """
    code = country_code.upper().strip()
    if len(code) != 2 or not code.isalpha():
        return False, 'Invalid country code.'

    with _lock:
        blocked = get_blocked_countries()
        if code not in blocked:
            return False, f'{code} is not currently blocked.'

        setname = _IPSET_PREFIX + code.lower()

        # Remove iptables rule
        _run(['iptables', '-D', 'INPUT', '-m', 'set', '--match-set', setname, 'src', '-j', 'DROP'])

        # Destroy ipset
        _run(['ipset', 'destroy', setname])

        # Update persistence
        blocked.remove(code)
        _save_blocked(blocked)

        country_name = dict(COUNTRY_LIST).get(code, code)
        logger.info('UNBLOCKED country=%s (%s)', code, country_name)
        return True, f'{country_name} ({code}) unblocked.'


def restore_blocks():
    """Restore all blocked countries (call on boot/service start)."""
    blocked = get_blocked_countries()
    for code in blocked:
        block_country(code)


def get_all_countries_with_status():
    """Return full country list with blocked status for UI."""
    blocked = set(get_blocked_countries())
    result = []
    for code, name in COUNTRY_LIST:
        result.append({
            'code': code,
            'name': name,
            'blocked': code in blocked,
        })
    return result
