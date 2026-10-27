# Wire protocol (as observed)

Documented here for **interoperability**. Everything below is little-endian.
"Unknown" means the field is carried through unchanged by the stock server and its meaning was not needed.

## Transport and discovery

* TCP, default port **7575** (plain). A separate TLS port (`SSLPort`) exists; it is not implemented here.
* Auto-Find is plain DNS-SD: service `_vhusb._tcp.local`, instance `<friendly name>`, SRV -> `<host>.local:port`,
  TXT = one string, the server serial. The SSL variant uses `_ssl_vhusb._tcp`. Clients send mDNS PTR queries.
* The server pings every 4 s (`PingInterval`); the client pings about once a second.

## Framing

```
frame   = u32 comp_len | u32 uncomp_len | body
body    = message (33-byte header + payload), uncomp_len bytes after decompression
```

* `comp_len == 0`: the body is stored raw and is `uncomp_len` long. Otherwise the body is an **LZ4 block** of
  `comp_len` bytes that expands to `uncomp_len`. A receiver must accept both; a sender may always send raw.
* The stock peers compress messages larger than `CompressionLimit`. Maximum message size is 0x3200000.

## Message header (33 bytes)

| offset | size | meaning |
|-------:|-----:|---------|
| 0  | 1 | message type |
| 1  | 4 | URB timeout in ms (requests), 0 in replies |
| 5  | 4 | sequence number, echoed in the reply |
| 9  | 8 | unknown (zero) |
| 17 | 8 | opaque client cookie (a kernel pointer of the client driver), echoed in the reply |
| 25 | 4 | device id |
| 29 | 4 | payload length |

A reply is the request header with the new type, `timeout = 0` and the new payload length.

## Message types

| client -> server | reply | meaning |
|---|---|---|
| 0 hello | 1 server info | handshake |
| 2 | 17 (empty) | keep-alive |
| 9 | one 16 per device | list devices |
| 10 | 11 (empty) | ping |
| 15 | - | answer to the server's type 12 ping (`u32` time, echoed) |
| 25 bind | 39, then broadcast 16 | start using a device |
| 35 unbind | 7, then broadcast 16 | stop using a device |
| 13 control URB | 14 | control transfer |
| 18 / 74 bulk-interrupt URB (74 = with streams) | 19 | bulk/interrupt transfer |
| 22 | 23 | reset device (`s32` status) |
| 26 / 28 / 30 / 50 / 51 | 27 / 29 / 31 / 32 / 23 | endpoint operations (clear halt / reset pipe / abort ...), `s32` status |
| 20, 33, 36, 40-48, 59-91 | various | not implemented here (iso transfers, queries, renames, ...) |

Server-initiated: 12 (ping), 16 (device record, also for hot-plug), 7 (device vanished while in use), 24 (text).

### 0 hello (client -> server, 132 bytes)
`name[64]` (e.g. `" (user)"`), `host[64]`, then client version `major, minor, patch, flags`.

### 1 server info (724 bytes)
| offset | size | meaning |
|-------:|-----:|---------|
| 0 | 1 | 8 |
| 1 | 127 | server name |
| 129 | 37 | server serial |
| 166 | 2 | maximum devices (0 = unlimited) |
| 168 | 16 | GUID of this connection; the same GUID marks the user in device records |
| 184 | 4 | server version `4, 8, 8, 0` |
| 188 | 255 | server host name |
| 444 | 255 | name of the interface the client connected through |
| 700 | 23 | EasyFind (cloud) block, all zero when disabled |
| 723 | 1 | 1 |

### 16 device record (539 bytes; 4.8.x appends a 32-byte UTC timestamp string)
| offset | size | meaning |
|-------:|-----:|---------|
| 0 | 2+2 | VID, PID |
| 4 / 68 | 64 / 64 | vendor, product strings (`0x%04x` when the device has none) |
| 132 | 4 | device id |
| 136 | 1 | state: 0 gone, 1 free, 3 in use |
| 137 | 16 | GUID of the connection using it |
| 153 | 4 | IPv4 of that client |
| 157 | 64 | nickname |
| 221 / 222 | 1 / 1 | number of configurations / interfaces |
| 223 | 3 | class, subclass, protocol of the first interface |
| 226 | 64 | name of the client using it |
| 290 | 16 | IPv6 of that client |
| 306 | 64 | device serial |
| 434 | 64 | host name of the client using it |
| 499 | 1 | port number (informational) |
| 538 | 1 | number of ports for hubs |

A device removed from the bus is announced as the same record with **state 0**.

### 39 bind reply (65878 bytes)
`s32 status` (1 = ok; -1 error, -2 too many devices, -3 unauthorized, -5 too many clients, -8 password required),
`u8 speed` (1 full, 2 high, 3 super), 65553 bytes of raw descriptors (device descriptor followed by the full
configuration descriptor, zero padded), product string, device serial, server serial (128 bytes each).

### 13 / 14 control transfer
Request payload: 8 unknown bytes, the 8-byte SETUP packet, then the data for OUT requests.
Reply payload: SETUP, `s32 status`, `u32 actual length`, then `wLength` bytes of data for IN requests.
A stalled request returns status -32.

### 18 / 19 bulk and interrupt transfer
Request payload: `u8 endpoint` + 3 zero bytes, `u8 flags`, `u32 type`, `u32 length`, then the data for OUT.
Reply payload: `s32 status-or-length` (bytes transferred, or a negative errno), then the data for IN requests
padded to the requested length.

Error numbers are Linux errnos: -19 no device, -32 stall, -110 timeout, -75 overflow, -5 I/O error.

### 66 / 67 device password
Header `device id` selects the device; the payload is the password (at most 127 bytes, no terminator needed). The reply
(type 67) has an empty payload and the same device id. The stock client sends the **32 lowercase hex digits of
`md5(password)`** (verified with client 6.0.3, `md5("hunter22hunter") = 4df1d2da...`), not the password itself. The
server keeps the value per connection and device; a bind (type 25) of a protected device that does not match is answered
with status **-8** (the client then shows *Please enter the password to use this device*, sends type 66 and binds again).
In the stock server this is a paid feature; this implementation checks it unconditionally, for free.

### 42 device nickname
Payload: `u16 vid`, `u16 pid`, `u32 device id`, `char nickname[64]` (empty removes it) and, from payloads of 200 bytes
upward, the device serial string at offset 72. The server stores the name, then sends the device record again (type 16,
nickname at record offset 157) to every client. If the change is refused the server sends a type 24 text message
`INSUFFICIENT_PERMISSIONS_MSG`.

## SSL (TLS)

* With a certificate configured the stock server listens on TCP **7574** (`SSLPort`) with mbedTLS; settings `SSLCert`,
  `SSLCAFile`, `SSLCRLFile`, `SSLUseClientCerts`. It announces `_ssl_vhusb._tcp` with the instance name
  instance `<friendly name> (SSL)`, SRV port 7574 and the same TXT (server serial) as the plain service.
* The protocol inside the TLS connection is identical (same framing and messages).
* The stock client (6.0.3) connects with TLS 1.2 (80 cipher suites, extensions: signature algorithms, supported groups,
  EC point formats, encrypt-then-MAC, extended master secret, session ticket; **no SNI**), verifies the server
  certificate against the file set in *Advanced Settings -> Certificate Authority File* (`/General/SSLCAFile`) and does
  not verify the host name. It does not try an SSL hub at all unless that file is set and loadable (backslashes in
  `vhui.ini` must be written as `/`). Servers are recognised by serial number: two servers with the same serial are shown once.

## Behaviour notes

* The device record's user GUID/name/host are filled while a device is in use so every client can show who has it.
* Requests for a device that is not bound to the sending connection are answered with -19.
* After a bind the client immediately resets the device (type 22) and reads descriptors again via type 13.
