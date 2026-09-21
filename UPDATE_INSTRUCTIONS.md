# GitHub Update 2

Replace/update these files in the repository:

```text
README.md
STATUS.md
CONTINUE_HERE.md
.gitignore
docs/RARITY_SYSTEM.md
docs/GHIDRA_FINDINGS.md
.github/ISSUE_TEMPLATE/01-aux-record-0x04.md
.github/ISSUE_TEMPLATE/02-database-reconstruction.md
.github/ISSUE_TEMPLATE/03-network-mock.md
```

Suggested commit message:

```text
Expand preservation documentation and research handoff
```

Important fix:

```text
real_backend_capture/
mock/real_backend_capture/
```

are now ignored so diagnostic shadow captures are not accidentally committed.
