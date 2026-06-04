@echo off
rem Shared settings for MikroTik AmneziaWG helper scripts.
rem Do not put AmneziaWG private keys or VPN config secrets here.

set "ROUTER_IP=192.168.88.1"
set "ROUTER_USER=admin"
set "ROUTER=%ROUTER_USER%@%ROUTER_IP%"

rem Explicit SSH key. Password-based automation is intentionally avoided.
set "SSH_KEY_PATH=%~dp0keys\codex_mikrotik_rsa"
set "SSH_COMMON_OPTS=-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3"

rem Required for encrypted MikroTik binary backups. Change before running 00_backup.bat.
set "BACKUP_PASSWORD=Ggert!43"
set "INCLUDE_SENSITIVE_EXPORT=0"
set "CLEAN_REMOTE_BACKUP_FILES=1"

rem Router facts from diagnostics.
set "ROUTEROS_VERSION=7.18.2"
set "ROUTER_ARCH=arm64"

rem Optional local path to RouterOS container package.
set "CONTAINER_NPK_PATH=container-7.18.2-arm64.npk"
set "CONTAINER_IMAGE=awg-proxy-arm64-7.20-Docker.tar.gz"

rem RouterOS device-mode flags needed by timbrs awg-proxy scripts.
set "DEVICE_MODE_FLAGS=container=yes fetch=yes"

rem Export from https://timbrs.github.io/amneziawg-mikrotik-c/configurator.html
rem Keep secrets only in local .rsc files, not in these BAT files.
set "AWG_GENERATED_RSC=awg-generated.rsc"
set "REMOTE_AWG_RSC=awg-generated.rsc"

rem Working WireGuard and container parameters from successful Stage1/1.5.
set "WG_INTERFACE=wg-awg-proxy"
set "WG_ADDRESS=10.8.1.6"
set "WG_TEST_IP=1.1.1.1"
set "AWG_SRC_PORT=40000"

set "OLD_VETH=veth-awg-proxy"
set "OLD_CONTAINER_ENV=awg-proxy-env"
set "OLD_CONTAINER_COMMENT=awg-proxy"
set "OLD_CONTAINER_SUBNET=172.18.9.104/30"
set "OLD_CONTAINER_GATEWAY=172.18.9.105"
set "OLD_CONTAINER_IP=172.18.9.106"

set "USB_FS_UUID=1f7d7ab6-b784-4133-a01c-5a5c62dbc345"
set "USB_MOUNT=awg-usb"
set "USB_VETH=veth-awg-proxy-usb"
set "USB_CONTAINER_ENV=awg-proxy-usb-env"
set "USB_CONTAINER_COMMENT=awg-proxy-usb"
set "USB_CONTAINER_ROOT=awg-usb/awg-proxy-stable"
set "USB_CONTAINER_SUBNET=172.18.9.108/30"
set "USB_CONTAINER_GATEWAY=172.18.9.109"
set "USB_CONTAINER_IP=172.18.9.110"

rem OpenCCK policy routing.
set "LAN_INTERFACE_LIST=LAN"
set "LAN_SOURCE_LIST=awg_lan_sources"
set "LAN_SOURCE_CIDRS=192.168.88.0/24"
set "CONNECTION_MARK=awg-opencck"
set "ROUTING_TABLE=to-awg"
set "OPENCCK_LIST_SLOTS=awg_vpn_ip4_a awg_vpn_ip4_b"
set "OPENCCK_ENTRY_TIMEOUT=7d"
set "FORCE_IP_LIST=awg_force_ip4"
set "FORCE_ENTRY_TIMEOUT=2d"
set "FORCE_LIST_SLOTS=awg_force_ip4_a awg_force_ip4_b"
set "DNS_DYNAMIC_LIST=awg_dns_ip4"
set "DIRECT_IP_LIST=awg_direct_ip4"
set "DIRECT_FWD_RESOLVER=77.88.8.8"
set "DIRECT_DNS_REGEXPS=(^|.*\.)(avito|gosuslugi|ozon|wildberries|sberbank|sber|tbank|tinkoff)\.ru$ (^|.*\.)(avito\.st|bank\.yandex\.ru|yandexbank\.ru)$"
set "DIRECT_DNS_COMMENTS=awg-direct-fwd-ru-core awg-direct-fwd-ru-extra"
set "DIRECT_PREWARM_DOMAINS=avito.ru www.avito.ru gosuslugi.ru ozon.ru wildberries.ru sber.ru sberbank.ru tbank.ru tinkoff.ru bank.yandex.ru yandexbank.ru"
set "DIRECT_ENTRY_TIMEOUT=1h"
set "DIRECT_CONNTRACK_CLEANUP_MAX_IPS=128"
set "DOH_RESOLVER_LIST=awg_doh_resolvers"
set "OPENCCK_GUARD_EVERY=1000"
set "OPENCCK_MIN_FREE_BYTES=367001600"
set "MIN_FREE_MEMORY_MB=350"
set "OPENCCK_STATUS_FILE=awg-usb/opencck-import-status.txt"
set "OPENCCK_REMOTE_RSC=awg-usb/awg_policy_update.rsc"
set "SELFHEAL_REMOTE_RSC=awg-usb/awg_selfheal.rsc"

rem Cloud policy update. Set CLOUD_ARTIFACT_BASE_URL after GitHub Pages/Release publishing is configured.
set "CLOUD_ARTIFACT_BASE_URL=https://CHANGE-ME.example.invalid/awg-policy"
set "CLOUD_FORCE_MANIFEST=force-manifest.txt"
set "CLOUD_FULL_MANIFEST=full-policy-manifest.txt"
set "CLOUD_POLICY_STATE_FILE=awg-usb/awg-policy-state.txt"
set "CLOUD_WORK_DIR=awg-usb"
set "CLOUD_FORCE_MIN_COUNT=50"
set "CLOUD_OPENCCK_MIN_COUNT=30000"
set "CLOUD_FULL_CHUNK_SIZE=5000"
set "CLOUD_WATCHDOG_STALE_HOURS=26"

rem DNS-driven policy layer for YouTube/SmartTube and AI services.
set "TARGET_DOMAINS=chatgpt.com openai.com api.openai.com auth.openai.com claude.ai anthropic.com console.anthropic.com gemini.google.com bard.google.com aistudio.google.com makersuite.google.com ai.google.dev notebooklm.google.com labs.google accounts.google.com clients6.google.com ogs.google.com youtube.com www.youtube.com m.youtube.com music.youtube.com googlevideo.com redirector.googlevideo.com youtubei.googleapis.com i.ytimg.com ytimg.com ggpht.com googleapis.com gstatic.com googleusercontent.com telegram.org t.me web.telegram.org instagram.com www.instagram.com i.instagram.com b.i.instagram.com graph.instagram.com api.instagram.com gateway.instagram.com edge-chat.instagram.com z-m-gateway.facebook.com mqtt-mini.facebook.com cdninstagram.com scontent.cdninstagram.com static.cdninstagram.com fbcdn.net fbsbx.com facebook.com graph.facebook.com connect.facebook.net"
set "ROUTER_DNS_CACHE_PATTERNS=googlevideo youtube ytimg ggpht googleapis gstatic googleusercontent chatgpt openai claude anthropic gemini bard aistudio makersuite notebooklm labs.google accounts.google clients6.google ogs.google telegram t.me telegra"
set "ENABLE_DNS_REDIRECT=1"
set "ENABLE_QUIC_BLOCK=1"
set "ENABLE_DOT_BLOCK=1"
set "ENABLE_DOH_RESOLVER_BLOCK=1"
set "ENABLE_TELEGRAM_IPV6_BLOCK=1"
set "MSS_CLAMP_VALUE=1220"

rem Discord voice/WebRTC policy layer.
rem Add only devices that actually use Discord voice. Keep this narrow, not 192.168.88.0/24.
set "DISCORD_CLIENT_LIST=awg_discord_clients"
set "DISCORD_CLIENT_CIDRS=192.168.88.203/32 192.168.88.205/32 192.168.88.215/32 192.168.88.217/32 192.168.88.236/32 192.168.88.238/32 192.168.88.239/32 192.168.88.241/32 192.168.88.243/32 192.168.88.244/32 192.168.88.247/32"
rem Optional MAC list for IPv6 UDP blocking, format: AA:BB:CC:DD:EE:FF separated by spaces.
set "DISCORD_CLIENT_MACS="
set "DISCORD_CONTROL_LIST=awg_discord_control_ip4"
set "DISCORD_ACTIVE_CLIENTS=awg_discord_active_clients"
set "DISCORD_VOICE_LIST=awg_discord_voice_ip4"
set "DISCORD_VOICE_EXCLUDE_LIST=awg_discord_voice_exclude_ip4"
set "DISCORD_VOICE_EXCLUDE_RANGES=224.0.0.0/4 255.255.255.255/32 127.0.0.0/8 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
set "DISCORD_CONTROL_DOMAINS=discord.com discord.gg gateway.discord.gg discord.media"
set "DISCORD_ACTIVE_TIMEOUT=15m"
set "DISCORD_VOICE_TIMEOUT=6h"
set "DISCORD_VOICE_PORTS=443,3478,19302,50000-65535"
set "ENABLE_DISCORD_VOICE_LEARN=1"
set "ENABLE_DISCORD_IPV6_UDP_BLOCK=1"

rem Telegram official CIDR list from https://core.telegram.org/resources/cidr.txt
set "TELEGRAM_FORCE_RANGES=91.108.56.0/22 91.108.4.0/22 91.108.8.0/22 91.108.16.0/22 91.108.12.0/22 149.154.160.0/20 91.105.192.0/23 91.108.20.0/22 185.76.151.0/24"
set "TELEGRAM_FORCE_RANGES6=2001:b28:f23d::/48 2001:b28:f23f::/48 2001:67c:4e8::/48 2001:b28:f23c::/48 2a0a:f280::/32"
set "TELEGRAM_IPV6_LIST=awg_telegram_ip6"
set "TELEGRAM_TEST_IPS=149.154.167.50 149.154.167.41 149.154.175.100 91.108.56.130 185.76.151.30"
set "SELFHEAL_TIMEOUT=1d"

rem Meta/Instagram DNS-poisoning protection.
set "META_DOMAINS=instagram.com www.instagram.com i.instagram.com b.i.instagram.com graph.instagram.com api.instagram.com gateway.instagram.com edge-chat.instagram.com z-m-gateway.facebook.com mqtt-mini.facebook.com cdninstagram.com scontent.cdninstagram.com static.cdninstagram.com fbcdn.net fbsbx.com facebook.com graph.facebook.com connect.facebook.net"
set "META_CRITICAL_DOMAINS=instagram.com i.instagram.com scontent.cdninstagram.com facebook.com"
set "META_BAD_DNS_LIST=awg_bad_dns_ip4"
set "META_BAD_DNS_SEEDS=188.186.146.208"
set "META_FWD_RESOLVER_CANDIDATES=1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4"
set "META_DNS_ROUTING_TABLE=to-awg-dns"
set "META_CONNTRACK_CLEANUP_MAX_BAD_IPS=5"

rem Default VPN categories. Heavy P2P/game categories are intentionally excluded.
set "OPENCCK_DEFAULT_GROUPS=ai anime discord messengers porn socials video youtube"
set "OPENCCK_CORE_FALLBACK_GROUPS=ai discord youtube"
set "OPENCCK_HEAVY_GROUPS=torrent games"
set "GENERATE_HEAVY_LIST=0"
set "INCLUDE_HEAVY_GROUPS_IN_DEFAULT=0"

rem Backward-compatible name used by older scripts.
set "ROUTER_OPENCCK_RSC=%OPENCCK_REMOTE_RSC%"

rem Rollback defaults.
set "RUN_TIMBRS_UNINSTALL=0"
set "REMOVE_OPENCCK_LISTS=0"
