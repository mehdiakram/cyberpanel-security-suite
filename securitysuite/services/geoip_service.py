"""
CyberPanel Security Suite — GeoIP Service
IP geolocation using free ip-api.com (no API key needed).
Includes in-memory caching and batch lookup support.
"""

import json
import time
import logging
import threading
try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
except ImportError:
    from urllib2 import Request, urlopen, URLError

logger = logging.getLogger('securitysuite')

API_SINGLE = 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,lat,lon'
API_BATCH = 'http://ip-api.com/batch?fields=query,status,country,countryCode,city,isp,lat,lon'

# ---------------------------------------------------------------------------
# Cache (thread-safe, in-memory)
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_cache = {}  # {ip: {data..., _ts: timestamp}}
_CACHE_TTL = 3600  # 1 hour


def _cache_get(ip):
    with _cache_lock:
        entry = _cache.get(ip)
        if entry and (time.time() - entry.get('_ts', 0)) < _CACHE_TTL:
            return entry
    return None


def _cache_set(ip, data):
    with _cache_lock:
        data['_ts'] = time.time()
        _cache[ip] = data


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------

def lookup_ip(ip_str):
    """
    Look up geolocation for a single IP.
    Returns dict: {country, countryCode, city, isp, lat, lon}
    """
    ip_str = ip_str.strip()
    cached = _cache_get(ip_str)
    if cached:
        result = dict(cached)
        result.pop('_ts', None)
        return result

    try:
        url = API_SINGLE.replace('{ip}', ip_str)
        req = Request(url, headers={'User-Agent': 'CyberPanel-SecuritySuite/1.6'})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read().decode('utf-8'))

        if data.get('status') == 'success':
            result = {
                'ip': ip_str,
                'country': data.get('country', 'Unknown'),
                'countryCode': data.get('countryCode', '??'),
                'city': data.get('city', ''),
                'isp': data.get('isp', ''),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
            }
            _cache_set(ip_str, result)
            return result
    except Exception as exc:
        logger.warning('GeoIP lookup failed for %s: %s', ip_str, exc)

    return _unknown(ip_str)


def lookup_batch(ip_list):
    """
    Look up geolocation for multiple IPs (max 100 per batch).
    Returns list of dicts.
    """
    if not ip_list:
        return []

    results = []
    to_fetch = []

    # Check cache first
    for ip in ip_list:
        ip = ip.strip()
        cached = _cache_get(ip)
        if cached:
            result = dict(cached)
            result.pop('_ts', None)
            results.append(result)
        else:
            to_fetch.append(ip)

    if not to_fetch:
        return results

    # Batch API (max 100 per request)
    for i in range(0, len(to_fetch), 100):
        batch = to_fetch[i:i + 100]
        try:
            payload = json.dumps(batch).encode('utf-8')
            req = Request(
                API_BATCH,
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'CyberPanel-SecuritySuite/1.7',
                }
            )
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read().decode('utf-8'))

            for item in data:
                ip = item.get('query', '')
                if item.get('status') == 'success':
                    result = {
                        'ip': ip,
                        'country': item.get('country', 'Unknown'),
                        'countryCode': item.get('countryCode', '??'),
                        'city': item.get('city', ''),
                        'isp': item.get('isp', ''),
                        'lat': item.get('lat', 0),
                        'lon': item.get('lon', 0),
                    }
                else:
                    result = _unknown(ip)
                _cache_set(ip, result)
                results.append(result)

            # Rate limit: ip-api allows 15 requests/minute for batch
            if i + 100 < len(to_fetch):
                time.sleep(1)

        except Exception as exc:
            logger.warning('GeoIP batch lookup failed: %s', exc)
            for ip in batch:
                results.append(_unknown(ip))

    return results


def get_country_stats(ip_list):
    """
    Return country statistics from a list of IPs.
    Returns sorted list: [{countryCode, country, count, ips: []}]
    """
    geo_data = lookup_batch(ip_list)
    countries = {}

    for item in geo_data:
        code = item.get('countryCode', '??')
        if code not in countries:
            countries[code] = {
                'countryCode': code,
                'country': item.get('country', 'Unknown'),
                'count': 0,
                'ips': [],
            }
        countries[code]['count'] += 1
        countries[code]['ips'].append({
            'ip': item.get('ip', ''),
            'city': item.get('city', ''),
            'isp': item.get('isp', ''),
        })

    # Sort by count descending
    result = sorted(countries.values(), key=lambda x: x['count'], reverse=True)
    return result


def get_country_flag(country_code):
    """Convert country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return '🏴'
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())


def _unknown(ip):
    return {
        'ip': ip,
        'country': 'Unknown',
        'countryCode': '??',
        'city': '',
        'isp': '',
        'lat': 0,
        'lon': 0,
    }
