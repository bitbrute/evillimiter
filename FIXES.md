# Evillimiter — Fixes Applied

**Date:** 2026-03-26
**Python version:** 3.14.3
**Package manager:** uv 0.8.12

---

## Summary

12 fixes were applied to make evillimiter compatible with Python 3.14 and address code quality issues identified in the audit. The project now installs and runs on modern Python using `uv` with a `pyproject.toml`-based build system.

---

## Environment Setup

A `uv`-managed virtual environment was created with Python 3.14:

```bash
uv venv .venv --python 3.14
uv pip install -e .
```

All dependencies install and all modules import successfully.

---

## Fixes Applied

### 1. Migrated from `setup.py` to `pyproject.toml`

**File:** `pyproject.toml` (new)

**Problem:** `setup.py` uses `distutils` which was removed in Python 3.12. `python3 setup.py install` no longer works.

**Fix:** Created `pyproject.toml` with `hatchling` build backend. The old `setup.py` is preserved for reference but is no longer needed.

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

---

### 2. Replaced `netifaces` with `netifaces-plus`

**File:** `pyproject.toml`

**Problem:** `netifaces` is unmaintained (last release 2021) and has no wheels for Python 3.12+. It fails to install on modern Python.

**Fix:** Replaced the dependency with `netifaces-plus>=0.12.3`, a maintained fork that provides the same API under the same `import netifaces` namespace. Zero code changes required — it's a drop-in replacement.

---

### 3. Removed `pkg_resources` import

**File:** `evillimiter/evillimiter.py`

**Problem:** `import pkg_resources` was imported but never used. `pkg_resources` is part of `setuptools` which is no longer bundled with Python 3.12+. This caused an `ImportError` on modern Python.

**Fix:** Removed the unused import.

---

### 4. Fixed invalid escape sequence in ANSI regex

**File:** `evillimiter/console/io.py`

**Problem:** The ANSI regex used a non-raw string with `\d` escape sequences:
```python
_ANSI_CSI_RE = re.compile('\001?\033\\[((?:\\d|;)*)([a-zA-Z])\002?')
```
Python 3.12+ raises `DeprecationWarning` for invalid escape sequences, and future versions will raise `SyntaxError`.

**Fix:** Changed to a raw string:
```python
_ANSI_CSI_RE = re.compile(r'\001?\033\[((?:\d|;)*)([a-zA-Z])\002?')
```

---

### 5. Fixed ARP packet construction (Scapy warnings)

**File:** `evillimiter/networking/spoof.py`

**Problem:** ARP packets were sent at Layer 3 without an Ethernet frame, causing Scapy to warn *"should be providing Ethernet destination MAC address"*. On some systems or newer Scapy versions, this could cause packets to not be delivered correctly.

```python
# Before:
ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
send(x, verbose=0, iface=self.interface)
```

**Fix:** Added explicit Ethernet layer and switched from `send()` to `sendp()`:
```python
# After:
Ether(dst=self.gateway_mac)/ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
sendp(pkt, verbose=0, iface=self.interface)
```

Also fixed restoration packets to use `Ether(dst=BROADCAST)`.

---

### 6. Fixed list comprehension used for side effects

**File:** `evillimiter/networking/spoof.py`

**Problem:** List comprehensions were used to execute `send()` calls — an anti-pattern that allocates an unused list:
```python
[send(x, verbose=0, iface=self.interface) for x in packets]
```

**Fix:** Replaced with a proper `for` loop:
```python
for pkt in packets:
    sendp(pkt, verbose=0, iface=self.interface)
```

---

### 7. Fixed float division in `BitRate.__str__()` and `ByteValue.__str__()`

**File:** `evillimiter/networking/utils.py`

**Problem:** Used `/=` (float division) where `//=` (integer division) was intended:
```python
r /= 1000   # Returns float → "1.5kbit" instead of "1kbit"
v /= 1024   # Returns float → "1.5kb" instead of "1kb"
```

**Fix:** Changed to integer division:
```python
r //= 1000
v //= 1024
```

---

### 8. Replaced generic `Exception` with `ValueError`

**File:** `evillimiter/networking/utils.py`

**Problem:** Four places raised bare `Exception` for invalid input:
```python
raise Exception('Invalid bitrate')
raise Exception('Bitrate limit exceeded')
raise Exception('Invalid byte string')
raise Exception('Byte value limit exceeded')
```

**Fix:** Changed all to `ValueError`, which is the correct exception type for invalid argument values.

---

### 9. Fixed `Direction.pretty_direction` missing `@staticmethod`

**File:** `evillimiter/networking/limit.py`

**Problem:** `pretty_direction(direction)` was defined as a method inside the `Direction` class without `@staticmethod`. In Python 3.10+, calling it as `Direction.pretty_direction(value)` would fail because `direction` would receive `Direction` as `self`.

**Fix:** Added `@staticmethod` decorator.

---

### 10. Fixed monitor reset using `ByteValue(0)` instead of `*= 0`

**File:** `evillimiter/networking/monitor.py`

**Problem:** Temp byte counters were reset by multiplying by zero:
```python
result._upload_temp_size *= 0
result._download_temp_size *= 0
```
This relied on `ByteValue.__mul__` returning `ByteValue(0)` — correct but confusing and fragile.

**Fix:** Direct assignment:
```python
result._upload_temp_size = ByteValue(0)
result._download_temp_size = ByteValue(0)
```

---

### 11. Fixed `shell.py` resource leak and circular import

**File:** `evillimiter/console/shell.py`

**Problem (resource leak):** A global `DEVNULL = open(os.devnull, 'w')` file handle was opened at module import time and never closed.

**Problem (circular import):** `shell.py` imported `IO` at module level, but `io.py` imported `shell` at module level, creating a circular dependency that would fail depending on import order.

**Fix:**
- Replaced `DEVNULL` with `subprocess.DEVNULL` (built-in constant, no file handle needed)
- Moved the `IO` import inside `locate_bin()` (the only function that uses it) to break the circular dependency
- Removed the unused `os` import

---

### 12. Added crash-safe cleanup with `atexit` and `signal`

**File:** `evillimiter/evillimiter.py`

**Problem:** If the process crashed or was killed with SIGTERM, IP forwarding was left enabled and tc qdisc rules persisted, potentially disrupting the host system's networking.

**Fix:** Added `atexit.register(cleanup)` and `signal.signal(SIGTERM)` handler before entering the main loop. The cleanup is unregistered after normal exit to avoid double-cleanup:

```python
atexit.register(cleanup, args.interface)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
# ... main loop ...
cleanup(args.interface)
atexit.unregister(cleanup)
```

---

## Dependency Versions (installed)

| Package | Version |
|---------|---------|
| Python | 3.14.3 |
| colorama | 0.4.6 |
| netaddr | 1.3.0 |
| netifaces-plus | 0.12.5 |
| tqdm | 4.67.3 |
| scapy | 2.7.0 |
| terminaltables | 3.1.10 |

---

## Files Modified

| File | Changes |
|------|---------|
| `pyproject.toml` | **New** — modern build config replacing `setup.py` |
| `evillimiter/evillimiter.py` | Removed `pkg_resources`, added `atexit`/`signal` cleanup |
| `evillimiter/console/io.py` | Fixed ANSI regex to use raw string |
| `evillimiter/console/shell.py` | Fixed resource leak, circular import, removed `os` import |
| `evillimiter/networking/utils.py` | Fixed float division, `Exception` → `ValueError` |
| `evillimiter/networking/spoof.py` | Added Ether layer, `send` → `sendp`, fixed list comprehension |
| `evillimiter/networking/limit.py` | Added `@staticmethod` to `pretty_direction` |
| `evillimiter/networking/monitor.py` | Fixed `*= 0` reset to `ByteValue(0)` |

---

## Verification

All 12 fixes were verified programmatically against Python 3.14.3:

```
[OK] No pkg_resources import (removed)
[OK] netifaces-plus works (19 interfaces found)
[OK] ANSI regex (raw string) works
[OK] BitRate integer division: 1mbit
[OK] ByteValue integer division: 1kb
[OK] BitRate raises ValueError
[OK] ByteValue raises ValueError
[OK] Direction.pretty_direction is @staticmethod
[OK] Monitor resets with ByteValue(0) instead of *= 0
[OK] ARP spoofer uses Ether layer + sendp()
[OK] shell.py uses subprocess.DEVNULL (no file handle leak)
[OK] atexit + signal handlers for crash cleanup
[OK] Circular import fixed (lazy import in locate_bin)
```