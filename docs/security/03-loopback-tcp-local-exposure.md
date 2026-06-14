# 03 — Loopback TCP listener is reachable by every local user

**Severity:** Low (defense-in-depth / hardening; the token still gates every
request)

**Affected code:**
- `server/.../TcpTransport.java` — bind to `InetAddress.getLoopbackAddress()`
- `server/.../ServerConfig.java` — `tcpEnabled` defaults to `true`

## What the issue is

The server binds a loopback TCP socket by default:

```java
this.serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
```

`127.0.0.1` is **not** a per-user boundary. On a multi-user host, *every* local
user (and every process, including unprivileged ones) can `connect()` to it. This
is unlike the Unix domain socket, which is a filesystem object guarded by
`0600`/`0700` permissions — i.e. genuinely restricted to the owning user. There
is also no peer-credential (`SO_PEERCRED`) check on accepted connections, so the
server never learns *which* local user connected.

With the shipped `AllowAllPolicy`, the shared token is therefore the **sole**
access control for any local process reaching the TCP port.

## The threat it poses

On a single-user developer machine this is fine, and the README correctly frames
the loopback bind as defense-in-depth. The concern is the **shared / multi-user
host**:

- Any local user can reach the full data and control planes over TCP and submit
  unlimited authentication attempts (see also finding 01 for the pre-auth DoS
  surface this opens).
- The token becomes a single shared secret defending a surface exposed to every
  account on the box. If it leaks (a stray env dump, a log from a misbehaving
  client, shoulder-surfing a `--token-file` path), any local user can use the KMS
  as the owner.
- Because there is no peer-uid check, the server cannot distinguish the intended
  owner from any other local caller even in principle.

This is a smaller risk than 01 or 02 — it is exploitation *surface*, not a
standalone vulnerability — but a KMS on shared infrastructure should minimize who
can even talk to it.

## The fix

- **Prefer the Unix socket and make TCP opt-in.** Default `tcpEnabled` to
  `false`; require an explicit `--tcp-port` (or env) to turn it on. The Unix
  socket already restricts access to the owning user via file permissions, which
  is the property you actually want on a shared host.
- **If TCP must be enabled, add a peer-uid check.** Where the platform supports
  it, read the connecting process's uid (`SO_PEERCRED` on Linux for Unix sockets;
  for TCP, peer credentials are not generally available — another reason to
  prefer Unix) and reject connections whose uid is not the server owner's.
- Keep the token requirement on **both** transports regardless (it already is).

## Why the fix works

Restricting *who can reach the endpoint* shrinks the attack surface to the set of
principals that should have access in the first place, so the shared token is no
longer the only thing standing between every local account and the key service.
File permissions on a Unix socket are enforced by the kernel at `connect()` time:
a process whose uid lacks access cannot even open the connection, so brute-force,
DoS, and token-replay attempts from other local users are stopped *before* they
reach application code. Making TCP opt-in applies the principle of least exposure
by default — the broad surface is present only when an operator deliberately
accepts the trade-off — while a peer-uid check enforces the same "owning user
only" boundary that the Unix socket gets for free.
