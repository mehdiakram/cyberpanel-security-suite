"""
CyberPanel Security Suite — URL Configuration
All routes are prefixed with /securitysuite/ when included in CyberPanel.
"""

from django.urls import path
from . import views

app_name = 'securitysuite'

urlpatterns = [
    # ── Page views ────────────────────────────────────────────────────────
    path('', views.overview, name='overview'),
    path('jails/', views.jails, name='jails'),
    path('banned-ips/', views.banned_ips, name='banned_ips'),
    path('logs/', views.logs_page, name='logs'),
    path('settings/', views.settings_page, name='settings'),
    path('geoip/', views.geoip_page, name='geoip'),
    path('country-block/', views.country_block_page, name='country_block'),
    path('whitelist/', views.whitelist_page, name='whitelist'),

    # ── AJAX API endpoints ────────────────────────────────────────────────
    path('api/status/', views.api_status, name='api_status'),
    path('api/jails/', views.api_jails, name='api_jails'),
    path('api/jail/<str:jail_name>/', views.api_jail_detail, name='api_jail_detail'),
    path('api/ban/', views.api_ban, name='api_ban'),
    path('api/unban/', views.api_unban, name='api_unban'),
    path('api/reload/', views.api_reload, name='api_reload'),
    path('api/logs/', views.api_logs, name='api_logs'),

    # ── GeoIP & Country Block API ─────────────────────────────────────────
    path('api/geoip/', views.api_geoip, name='api_geoip'),
    path('api/countries/', views.api_countries, name='api_countries'),
    path('api/country/block/', views.api_country_block, name='api_country_block'),
    path('api/country/unblock/', views.api_country_unblock, name='api_country_unblock'),

    # ── Whitelist API ─────────────────────────────────────────────────────
    path('api/whitelist/', views.api_whitelist, name='api_whitelist'),
    path('api/whitelist/add/', views.api_whitelist_add, name='api_whitelist_add'),
    path('api/whitelist/remove/', views.api_whitelist_remove, name='api_whitelist_remove'),
]
