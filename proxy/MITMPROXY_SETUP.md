# mitmproxy Setup

## Topology

```text
Android device
     |
     | Wi-Fi proxy
     v
Research PC :8080
     |
     v
mitmproxy / mitmdump
     |
     v
mock/dls_mock.py
```

## Start

```bat
mitmdump -s mock\dls_mock.py ^
  --listen-host 0.0.0.0 ^
  --listen-port 8080 ^
  --set connection_strategy=lazy
```

Verify:

```bat
netstat -ano | findstr :8080
```

## Android Wi-Fi proxy

```text
Proxy: Manual
Host: <PC LAN IP>
Port: 8080
```

## ADB checks

```bat
adb shell settings get global http_proxy
adb shell settings get global global_http_proxy_host
adb shell settings get global global_http_proxy_port
```

A `null` global value does not prove that no per-Wi-Fi proxy exists.

## HTTPS certificate

Each researcher should use their own local mitmproxy CA.

Never commit its private key.
