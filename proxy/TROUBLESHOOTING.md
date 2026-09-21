# Proxy / Mock Troubleshooting

## No requests appear

Check:

1. Is `mitmdump` running?
2. Is port 8080 listening?
3. Is Windows Firewall allowing inbound traffic?
4. Can the phone reach the PC?
5. Is the phone actually using the intended Wi-Fi?
6. Is mobile data/VPN/private DNS changing the path?
7. Is the proxy configured on the active Wi-Fi?
8. Is the game making a new request?
9. Is HTTPS interception accepted?
10. Was mitmdump restarted after changing cached/local data?

## Windows

```bat
netstat -ano | findstr :8080
```

## Android

```bat
adb shell settings get global http_proxy
adb shell settings get global global_http_proxy_host
adb shell settings get global global_http_proxy_port
```

## Changed DAT but old behavior remains

Possible cache/state issue.

Try:

1. stop `mitmdump`;
2. replace the DAT;
3. restart `mitmdump`;
4. retry the game flow.
