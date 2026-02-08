# profinet-py

A Python library for PROFINET IO communication.

## Features

- **DCP Discovery**: Find PROFINET devices on the network
- **DCE/RPC Communication**: Establish connections to IO-Devices
- **Parameter Read/Write**: Access device parameters via slot/subslot/index
- **IM0/IM1 Support**: Read device identification data
- **Cyclic I/O**: Real-time periodic data exchange
- **Alarm Handling**: Background alarm listener per IEC 61158-6-10
- **Cross-Platform**: Linux, Windows (via Npcap), macOS (via libpcap)

## Requirements

- Python 3.8+
- Administrator/root privileges (for raw Ethernet access)

### Platform-specific

| Platform | Raw Socket Backend | Extra Software |
|----------|-------------------|----------------|
| **Linux** | AF_PACKET (built-in) | None |
| **Windows** | Npcap (wpcap.dll) | Install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled |
| **macOS** | libpcap (built-in) | None |

## Installation

This package is not published on PyPI. Install from source:

```bash
git clone https://github.com/f0rw4rd/profinet.git
cd profinet
pip install -e .
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

## Credits

This project is a modernized fork of the original PROFINET library by **Alfred Krohmer**:

- **Original Repository**: https://github.com/alfredkrohmer/profinet
- **Original Author**: Alfred Krohmer (2015)

### Changes in this fork

- Cross-platform support (Windows via Npcap ctypes, macOS via libpcap ctypes)
- Windows friendly name resolution (e.g., "Ethernet 3") via registry lookup
- Cyclic I/O, alarm handling, high-level device API
- Updated for Python 3.8+ compatibility
- Added type hints, docstrings, proper package structure
- Improved error handling and logging

## License

This project maintains the same license as the original work.
See [LICENSE](LICENSE) for details.

## References

- [PROFINET Specification](https://www.profibus.com/technology/profinet)
- [Wireshark PROFINET/IO](https://wiki.wireshark.org/PROFINET/IO)
- [Npcap Download](https://npcap.com/)
