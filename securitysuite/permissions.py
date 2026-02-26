"""
CyberPanel Security Suite — Permissions & Rate Limiting
Decorators for admin-only access and API rate limiting.
Compatible with CyberPanel 2.4.4+
"""

import time
import functools
import threading
from django.http import JsonResponse, HttpResponseForbidden


# ---------------------------------------------------------------------------
# Admin-only access decorator (CyberPanel 2.4.4 compatible)
# ---------------------------------------------------------------------------

def admin_required(view_func):
    """
    Decorator that restricts access to CyberPanel admin users only.
    CyberPanel 2.4.4 stores userID in session and uses ACLManager for
    role-based access. Admin users have currentACL['admin'] == 1.
    """
    @functools.wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        try:
            user_id = request.session.get('userID')

            if not user_id:
                return _deny(request, 'You must be logged in to CyberPanel.')

            # Use CyberPanel's ACLManager to check admin role
            try:
                from loginSystem.models import Administrator
                admin = Administrator.objects.get(pk=user_id)
            except Exception:
                return _deny(request, 'Invalid user session.')

            # Check if user is admin (userID 1 is always admin)
            # Also try ACLManager for role-based check
            is_admin = (user_id == 1)  # Primary admin is always ID 1

            if not is_admin:
                try:
                    from plogical.acl import ACLManager
                    currentACL = ACLManager.loadedACL(user_id)
                    is_admin = (currentACL.get('admin', 0) == 1)
                except Exception:
                    is_admin = False

            if not is_admin:
                return _deny(request, 'Admin access required.')

            # Store admin info in request for views to use
            request.admin_user = admin
            return view_func(request, *args, **kwargs)

        except Exception:
            return _deny(request, 'Authentication error.')

    return _wrapped


def _deny(request, message):
    """Return appropriate denial response based on request type."""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'status': False,
            'error': message
        }, status=403)
    return HttpResponseForbidden(
        '<div style="font-family:system-ui;text-align:center;padding:80px 20px;">'
        '<h2 style="color:#ef4444;">403 — Permission Denied</h2>'
        f'<p style="color:#64748b;">{message}</p>'
        '<p><a href="/" style="color:#3b82f6;">← Back to CyberPanel</a></p>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple in-memory per-IP rate limiter (thread-safe)."""

    def __init__(self):
        self._lock = threading.Lock()
        # {ip: [timestamp, ...]}
        self._requests = {}

    def is_allowed(self, ip, max_requests=30, window_seconds=60):
        """Return True if the IP is within the rate limit window."""
        now = time.time()
        with self._lock:
            timestamps = self._requests.get(ip, [])
            # Purge expired entries
            timestamps = [t for t in timestamps if now - t < window_seconds]
            if len(timestamps) >= max_requests:
                self._requests[ip] = timestamps
                return False
            timestamps.append(now)
            self._requests[ip] = timestamps
            return True


_limiter = _RateLimiter()


def rate_limit(max_requests=30, window_seconds=60):
    """
    Decorator that rate-limits API views per client IP.
    Returns 429 if the limit is exceeded.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            ip = _get_client_ip(request)
            if not _limiter.is_allowed(ip, max_requests, window_seconds):
                return JsonResponse({
                    'status': False,
                    'error': 'Too many requests. Please try again later.'
                }, status=429)
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def _get_client_ip(request):
    """Extract client IP from request, respecting CyberPanel's CF header."""
    # CyberPanel uses HTTP_CF_CONNECTING_IP for Cloudflare
    ip = request.META.get('HTTP_CF_CONNECTING_IP')
    if ip:
        return ip
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')
