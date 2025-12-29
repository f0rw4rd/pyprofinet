# profinet-py

A Python library for PROFINET IO communication.

## Features

- **DCP Discovery**: Find PROFINET devices on the network
- **DCE/RPC Communication**: Establish connections to IO-Devices
- **Parameter Read/Write**: Access device parameters via slot/subslot/index
- **IM0/IM1 Support**: Read device identification data

## Requirements

- Python 3.8+
- Linux (requires raw sockets)
- Root privileges (for raw Ethernet access)

## Installation

```bash
pip install profinet-py
```

## Usage

```python
from profinet import ethernet_socket, get_mac, send_discover, read_response
from profinet import RPCCon, get_station_info, PNInM0

# Create raw socket on interface
sock = ethernet_socket("eth0", 3)
src_mac = get_mac("eth0")

# Discover PROFINET devices
send_discover(sock, src_mac)
devices = read_response(sock, src_mac)

for mac, info in devices.items():
    print(f"Found: {info['name']} at {info['ip']}")

# Connect to device and read IM0
station_info = get_station_info(sock, src_mac, "device-name")
conn = RPCCon(station_info)
conn.connect(src_mac)

# Read device identification (IM0)
iod = conn.read(api=0, slot=0, subslot=1, idx=PNInM0.IDX)
im0 = PNInM0(iod.payload)
print(im0)
```

## Credits

This project is a modernized fork of the original PROFINET library by **Alfred Krohmer**:

- **Original Repository**: https://github.com/alfredkrohmer/profinet
- **Original Author**: Alfred Krohmer (2015)

The original code provided the foundation for PROFINET IO-Controller communication
in Python, including DCP discovery and DCE/RPC parameter access.

### Changes in this fork

- Updated for Python 3.8+ compatibility
- Added type hints throughout
- Replaced star imports with explicit imports
- Added proper package structure
- Added docstrings and documentation
- Improved error handling
- Added logging support

## License

This project maintains the same license as the original work.
See [LICENSE](LICENSE) for details.

## References

- [PROFINET Specification](https://www.profibus.com/technology/profinet)
- [Wireshark PROFINET/IO](https://wiki.wireshark.org/PROFINET/IO)
- [RT-Labs PROFINET Basics](https://rt-labs.com/profinet/profinet-basics/)
