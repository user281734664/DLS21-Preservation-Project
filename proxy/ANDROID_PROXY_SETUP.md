# Android Proxy Setup

On the active Wi-Fi network:

```text
Proxy: Manual
Host: <PC LAN IP>
Port: 8080
```

Check that the phone is actually using the intended Wi-Fi path and not mobile data or a VPN.

Useful diagnostic:

```bat
adb shell settings get global http_proxy
```

A `null` result can still occur when the proxy is configured only on a specific Wi-Fi network.
