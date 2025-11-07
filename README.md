# ping – Minimal C++ ICMP Ping Tool

A lightweight, educational `ping` implementation in C++ using raw sockets.

## Usage

```bash
sudo ./ping [-c count] <host>
```

- `-c count`: Number of pings (default: 4)
- `<host>`: Hostname or IP (IPv4 only)

**Requires `sudo`** due to `SOCK_RAW`.

## How It Works

1. Resolves host to IPv4 address via `getaddrinfo`.
2. Creates raw ICMP socket (`IPPROTO_ICMP`).
3. Sends **Echo Request** (type 8) with:
   - Process ID as identifier
   - Sequence number
   - 56-byte payload
   - Correct ICMP checksum
4. Receives reply, verifies:
   - Type 0 (Echo Reply)
   - Matching ID and sequence
5. Measures RTT and prints stats.

> No checksum verification on receive (simplified for clarity).

## TODO

- [ ] Add **IPv6** support (`AF_INET6`, ICMPv6)
- [ ] Implement **traceroute** (`-I` style with TTL)

---

**Full technical breakdown:**  
[Read the blog post](https://mohe-things.netlify.app/blogs/how-ping-work)
```
