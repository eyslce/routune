## 特点概述

- 入站连接支持: HTTP, HTTPS, SOCKS5 服务端, TUN 设备*
- 出站连接支持: Shadowsocks(R), VMess, Trojan, Snell, SOCKS5, HTTP(S), Wireguard*
- 基于规则的路由: 动态脚本、域名、IP地址、进程名称和更多*
- Fake-IP DNS: 尽量减少 DNS 污染的影响, 提高网络性能
- 透明代理: 使用自动路由表/规则管理 Redirect TCP 和 TProxy TCP/UDP*
- Proxy Groups 策略组: 自动化的可用性测试 (fallback)、负载均衡 (load balance) 或 延迟测试 (url-test)
- 远程 Providers: 动态加载远程代理列表
- RESTful API: 通过一个全面的 API 就地更新配置

