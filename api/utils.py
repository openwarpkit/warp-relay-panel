import ipaddress


def check_warp(ip_to_check):
    # Основные диапазоны, которые часто ассоциируются с WARP/Gateway
    # Список может меняться, Cloudflare не публикует отдельный WARP-лист официально
    warp_cidrs = [
        "104.28.0.0/14",  # Основной диапазон для WARP
        "172.64.0.0/13",  # Общий диапазон Cloudflare (может включать WARP)
        "2a06:98c0::/29"  # IPv6 диапазон
    ]
    
    try:
        ip_obj = ipaddress.ip_address(ip_to_check)
        for cidr in warp_cidrs:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        return False
    except ValueError:
        return False