"""
CyberPanel Security Suite — Views (v1.8)
Page views and AJAX API endpoints for Fail2ban, GeoIP, and Country Blocking.
All views require admin access and include CSRF protection.
"""

import json
import logging
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_GET

from .permissions import admin_required, rate_limit
from .services import fail2ban_service, system_service
from .services import geoip_service, country_block_service

logger = logging.getLogger('securitysuite')


# ═══════════════════════════════════════════════════════════════════════════
# PAGE VIEWS
# ═══════════════════════════════════════════════════════════════════════════

@admin_required
def overview(request):
    return render(request, 'securitysuite/overview.html', {'active_page': 'overview'})


@admin_required
def jails(request):
    return render(request, 'securitysuite/jails.html', {'active_page': 'jails'})


@admin_required
def banned_ips(request):
    return render(request, 'securitysuite/banned_ips.html', {'active_page': 'banned_ips'})


@admin_required
def logs_page(request):
    return render(request, 'securitysuite/logs.html', {'active_page': 'logs'})


@admin_required
def settings_page(request):
    return render(request, 'securitysuite/settings.html', {'active_page': 'settings'})


@admin_required
def geoip_page(request):
    return render(request, 'securitysuite/geoip.html', {'active_page': 'geoip'})


@admin_required
def country_block_page(request):
    return render(request, 'securitysuite/country_block.html', {'active_page': 'country_block'})


# ═══════════════════════════════════════════════════════════════════════════
# AJAX API — Fail2ban
# ═══════════════════════════════════════════════════════════════════════════

@admin_required
@rate_limit(max_requests=60, window_seconds=60)
@require_GET
def api_status(request):
    try:
        installed = fail2ban_service.is_fail2ban_installed()
        if not installed:
            return JsonResponse({
                'status': True,
                'data': {'installed': False, 'active': False, 'jails': [], 'jail_count': 0}
            })
        data = fail2ban_service.get_status()
        data['installed'] = True
        return JsonResponse({'status': True, 'data': data})
    except Exception as exc:
        logger.exception('api_status error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=60, window_seconds=60)
@require_GET
def api_jails(request):
    try:
        overall = fail2ban_service.get_status()
        jails_data = []
        all_ips = set()
        for jail_name in overall.get('jails', []):
            info = fail2ban_service.get_jail_status(jail_name)
            if 'error' not in info:
                jails_data.append(info)
                for ip in info.get('banned_ips', []):
                    all_ips.add(ip)
        
        # Add ban times
        ban_times = system_service.get_ban_times(list(all_ips))
        for info in jails_data:
            info['banned_ips_with_time'] = [
                {'ip': ip, 'time': ban_times.get(ip, 'Unknown')} 
                for ip in info.get('banned_ips', [])
            ]
            
        return JsonResponse({'status': True, 'data': jails_data})
    except Exception as exc:
        logger.exception('api_jails error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=60, window_seconds=60)
@require_GET
def api_jail_detail(request, jail_name):
    try:
        info = fail2ban_service.get_jail_status(jail_name)
        if 'error' in info:
            return JsonResponse({'status': False, 'error': info['error']}, status=400)
            
        # Add ban times
        ban_times = system_service.get_ban_times(info.get('banned_ips', []))
        info['banned_ips_with_time'] = [
            {'ip': ip, 'time': ban_times.get(ip, 'Unknown')} 
            for ip in info.get('banned_ips', [])
        ]
        return JsonResponse({'status': True, 'data': info})
    except Exception as exc:
        logger.exception('api_jail_detail error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=20, window_seconds=60)
@csrf_protect
@require_POST
def api_ban(request):
    try:
        body = json.loads(request.body)
        jail_name = body.get('jail', '').strip()
        ip_addr = body.get('ip', '').strip()
        if not jail_name or not ip_addr:
            return JsonResponse({'status': False, 'error': 'Both jail and ip are required.'}, status=400)
        ok, msg = fail2ban_service.ban_ip(jail_name, ip_addr)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_ban error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=20, window_seconds=60)
@csrf_protect
@require_POST
def api_unban(request):
    try:
        body = json.loads(request.body)
        jail_name = body.get('jail', '').strip()
        ip_addr = body.get('ip', '').strip()
        if not jail_name or not ip_addr:
            return JsonResponse({'status': False, 'error': 'Both jail and ip are required.'}, status=400)
        ok, msg = fail2ban_service.unban_ip(jail_name, ip_addr)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_unban error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=10, window_seconds=60)
@csrf_protect
@require_POST
def api_reload(request):
    try:
        ok, msg = fail2ban_service.reload()
        return JsonResponse({'status': ok, 'message': msg})
    except Exception as exc:
        logger.exception('api_reload error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=30, window_seconds=60)
@require_GET
def api_logs(request):
    try:
        num_lines = min(int(request.GET.get('lines', 200)), 500)
        lines = system_service.read_log_file('fail2ban', num_lines)
        return JsonResponse({'status': True, 'data': lines})
    except Exception as exc:
        logger.exception('api_logs error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


# ═══════════════════════════════════════════════════════════════════════════
# AJAX API — GeoIP Analytics
# ═══════════════════════════════════════════════════════════════════════════

@admin_required
@rate_limit(max_requests=10, window_seconds=60)
@require_GET
def api_geoip(request):
    """Return banned IPs with GeoIP country data and stats."""
    try:
        # Collect all banned IPs
        overall = fail2ban_service.get_status()
        all_ips = []
        for jail_name in overall.get('jails', []):
            info = fail2ban_service.get_jail_status(jail_name)
            if 'error' not in info:
                for ip in info.get('banned_ips', []):
                    all_ips.append(ip)

        # Get country stats
        stats = geoip_service.get_country_stats(list(set(all_ips)))

        # Add flag emojis
        for item in stats:
            item['flag'] = geoip_service.get_country_flag(item['countryCode'])

        return JsonResponse({
            'status': True,
            'data': {
                'total_ips': len(all_ips),
                'countries': stats,
            }
        })
    except Exception as exc:
        logger.exception('api_geoip error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


# ═══════════════════════════════════════════════════════════════════════════
# AJAX API — Country Blocking
# ═══════════════════════════════════════════════════════════════════════════

@admin_required
@rate_limit(max_requests=30, window_seconds=60)
@require_GET
def api_countries(request):
    """Return list of all countries with blocked status."""
    try:
        data = country_block_service.get_all_countries_with_status()
        return JsonResponse({'status': True, 'data': data})
    except Exception as exc:
        logger.exception('api_countries error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=5, window_seconds=60)
@csrf_protect
@require_POST
def api_country_block(request):
    """Block all traffic from a country."""
    try:
        body = json.loads(request.body)
        code = body.get('code', '').strip()
        if not code:
            return JsonResponse({'status': False, 'error': 'Country code is required.'}, status=400)
        ok, msg = country_block_service.block_country(code)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_country_block error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)


@admin_required
@rate_limit(max_requests=5, window_seconds=60)
@csrf_protect
@require_POST
def api_country_unblock(request):
    """Unblock a country."""
    try:
        body = json.loads(request.body)
        code = body.get('code', '').strip()
        if not code:
            return JsonResponse({'status': False, 'error': 'Country code is required.'}, status=400)
        ok, msg = country_block_service.unblock_country(code)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_country_unblock error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)

# ═══════════════════════════════════════════════════════════════════════════
# AJAX API — Whitelist
# ═══════════════════════════════════════════════════════════════════════════

@admin_required
def whitelist_page(request):
    return render(request, 'securitysuite/whitelist.html', {'active_page': 'whitelist'})

@admin_required
@rate_limit(max_requests=30, window_seconds=60)
@require_GET
def api_whitelist(request):
    """Return list of all whitelisted IPs."""
    try:
        data = fail2ban_service.get_whitelist()
        return JsonResponse({'status': True, 'data': data})
    except Exception as exc:
        logger.exception('api_whitelist error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)

@admin_required
@rate_limit(max_requests=10, window_seconds=60)
@csrf_protect
@require_POST
def api_whitelist_add(request):
    """Add an IP to the whitelist."""
    try:
        body = json.loads(request.body)
        ip = body.get('ip', '').strip()
        if not ip:
            return JsonResponse({'status': False, 'error': 'IP address is required.'}, status=400)
        ok, msg = fail2ban_service.add_to_whitelist(ip)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_whitelist_add error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)

@admin_required
@rate_limit(max_requests=10, window_seconds=60)
@csrf_protect
@require_POST
def api_whitelist_remove(request):
    """Remove an IP from the whitelist."""
    try:
        body = json.loads(request.body)
        ip = body.get('ip', '').strip()
        if not ip:
            return JsonResponse({'status': False, 'error': 'IP address is required.'}, status=400)
        ok, msg = fail2ban_service.remove_from_whitelist(ip)
        return JsonResponse({'status': ok, 'message': msg})
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)
    except Exception as exc:
        logger.exception('api_whitelist_remove error: %s', exc)
        return JsonResponse({'status': False, 'error': str(exc)}, status=500)
