# Final GitHub update

This ZIP is an **update overlay** for:

```text
user281734664/DLS21-Preservation-Project
```

## Upload

1. Extract this ZIP on your computer.
2. Open the repository on GitHub.
3. Choose **Add file -> Upload files**.
4. Drag the **contents** of the extracted folder into the repository root.
5. Allow GitHub to replace `README.md` and `.gitignore`.
6. Commit with:

```text
Add reproducible LAB APK builder and support information
```

Do **not** upload the ZIP itself as the final repository content.

## Files included

```text
README.md
.gitignore
tools/make_lab.py
tools/make_lab_windows.bat
patches/network_security_config.xml
docs/APK_PATCHING.md
UPLOAD_TO_GITHUB.md
```

## Do not commit

- original DLS21 APKs
- generated LAB APKs
- `.dls21-lab.keystore`
- private signing keys/passwords
- mitmproxy private CA keys
- private diagnostic/account captures
