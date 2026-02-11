# profinet-py

A Python library for PROFINET IO communication, acting as an IO-Controller.

## Features

- **DCP Discovery & Configuration**: Find devices, set IP/name, signal LEDs, factory reset with full SET response validation
- **DCE/RPC Communication**: Establish Application Relationships (AR) and perform acyclic read/write via slot/subslot/index
- **I&M Records**: Read/write Identification & Maintenance data (IM0-IM5)
- **Cyclic I/O**: Real-time periodic data exchange (RT_CLASS_1)
- **Alarm Handling**: Background alarm listener per IEC 61158-6-10
- **Diagnosis Parsing**: Channel, extended channel, and qualified channel diagnosis decoding
- **Vendor Registry**: 2100+ PROFINET vendor IDs with name lookup
- **Declarative Parsing**: Binary protocol parsing via [construct](https://construct.readthedocs.io/) library
- **Cross-Platform**: Linux (AF_PACKET), Windows (Npcap), macOS (libpcap)
- **High-level API**: `ProfinetDevice` class and `scan()` for quick device interaction

## Requirements

- Python 3.10+
- Administrator/root privileges (for raw Ethernet access)
- `construct>=2.10`

### Platform-specific

| Platform | Raw Socket Backend | Extra Software |
|----------|-------------------|----------------|
| **Linux** | AF_PACKET (built-in) | None |
| **Windows** | Npcap (wpcap.dll) | Install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled |
| **macOS** | libpcap (built-in) | None |

## Installation

```bash
pip install profinet-py
```

From source:

```bash
git clone https://github.com/f0rw4rd/profinet.git
cd profinet
pip install -e ".[dev]"
```

## Usage

```python
import profinet

# Discover all PROFINET devices on the network
for device in profinet.scan("eth0", timeout=5):
    print(f"Found: {device.name} at {device.ip} ({device.mac})")
```

On Windows, use the adapter's friendly name:

```python
for device in profinet.scan("Ethernet 3", timeout=5):
    print(f"Found: {device.name} at {device.ip}")
```

### Low-level DCP + RPC

```python
from profinet.util import ethernet_socket, get_mac
from profinet.dcp import send_discover, read_response
from profinet.rpc import RPCCon

# Create raw socket on interface
sock = ethernet_socket("eth0")
src_mac = get_mac("eth0")

# Discover PROFINET devices
send_discover(sock, src_mac)
responses = read_response(sock, src_mac, timeout_sec=5)

sock.close()
```

### CLI

```bash
# Discover devices
profinet -i eth0 discover

# Read I&M0 from device
profinet -i eth0 read-inm0 device-name

# Read raw record
profinet -i eth0 read device-name --slot 0 --subslot 1 --index 0xAFF0

# Cyclic IO monitoring (default 32ms cycle)
profinet -i eth0 cyclic device-name --gsdml device.xml

# Custom cycle time
profinet -i eth0 cyclic device-name --gsdml device.xml --cycle-ms 16
```

## Credits

This project is a modernized fork of the original PROFINET library by **Alfred Krohmer**:

- **Original Repository**: https://github.com/alfredkrohmer/profinet
- **Original Author**: Alfred Krohmer (2015)

### Changes in this fork

- Cross-platform support (Windows via Npcap ctypes, macOS via libpcap ctypes)
- Dropped Python 3.8/3.9 (EOL), targets Python 3.10+
- Migrated all binary parsing from `struct` to `construct` library for declarative, readable protocol definitions
- Fixed 5 protocol bugs verified against Wireshark's PROFINET dissector and IEC 61158-6-10:
  - DCP Option 0x04 is Reserved (not LLDP)
  - Block Type 0x0012 is ExpectedIdentificationData (not QualifiedChannelDiagnosis)
  - RT_CLASS_1 frame ID range starts at 0x8000 (not 0xC000)
  - Device Suboption 0x09 does not exist in the spec
  - DCP Identify uses separate Frame IDs for request (0xFEFE) and response (0xFEFF)
- DCP SET operations now validate response block error codes instead of silently succeeding
- Diagnosis parsing module with channel/extended/qualified channel support
- Alarm notification parsing and background alarm listener
- Cyclic I/O controller for RT_CLASS_1 periodic data exchange
- High-level `ProfinetDevice` API and `scan()`/`scan_dict()` convenience functions
- 2100+ vendor ID registry with lookup
- CLI tool for discovery, I&M reading, and raw record access
- 570+ unit tests, 150+ Docker-based integration tests against p-net device emulator
- Type hints, ruff linting, mypy checking

## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)

## License

GPLv3. See [LICENSE](LICENSE) for details.

## References

- [PROFINET Specification](https://www.profibus.com/technology/profinet)
- [Wireshark PROFINET/IO](https://wiki.wireshark.org/PROFINET/IO)
- [construct library](https://construct.readthedocs.io/)
