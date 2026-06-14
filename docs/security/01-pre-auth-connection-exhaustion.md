# 01 — Pre-authentication connection & slow-read resource exhaustion

**Severity:** Medium (local, unauthenticated denial of service)
**Status:** ✅ Fixed (idle-timeout watchdog + concurrent-connection cap)

**Affected code:**
- `server/.../TcpTransport.java` — `acceptLoop()`
- `server/.../UnixSocketTransport.java` — `acceptLoop()`
- `server/.../BoundedLineReader.java` — `readLine()`
- `server/.../KmsServer.java` — `Executors.newVirtualThreadPerTaskExecutor()`

## What the issue is

Every accepted socket is dispatched to an **unbounded** virtual-thread executor,
and **no read timeout is ever set** on the connection. The request reader blocks
in `in.read()` until it sees a newline:

```java
// BoundedLineReader.readLine()
while ((read = in.read()) != -1) {   // blocks here, forever, with no timeout
  ...
  if (buffer.size() >= maxFrameBytes) {
    throw new FrameTooLargeException(maxFrameBytes);
  }
  buffer.write(read);
}
```

```java
// KmsServer
this.executor = Executors.newVirtualThreadPerTaskExecutor(); // no concurrency cap
```

The `--max-frame-bytes` limit (default 1 MiB) bounds *one line*. It does **not**
bound how many connections exist at once, nor how long each may stay open. All of
this happens **before any token is validated** — authentication is per-request,
inside `KmsRequestHandler.handle`, which is never reached until a full line
arrives.

## The threat it poses

Any local process — every local user, in the case of the loopback TCP listener —
can mount a denial of service without knowing the token:

1. **Connection flooding.** Open tens of thousands of connections. Each consumes
   a file descriptor, a virtual thread, and a `ByteArrayOutputStream` that can
   grow to ~1 MiB. A few thousand half-filled frames is multiple gigabytes of
   heap, plus file-descriptor exhaustion.
2. **Slowloris.** Connect and send one byte every few seconds (never a newline).
   The reader blocks indefinitely; the connection is pinned open forever. A
   handful of these, repeated, exhausts descriptors and memory and starves
   legitimate clients.

Because the KMS is a single point of failure for everything that depends on it,
taking it offline can cascade: dependent services can no longer encrypt or
decrypt.

## The fix

Two independent bounds were added, controlled by new configuration
(`--idle-timeout-ms` / `MINIKMS_IDLE_TIMEOUT_MS`, default 30 000;
`--max-connections` / `MINIKMS_MAX_CONNECTIONS`, default 256):

1. **An idle-timeout watchdog** wraps every read of the next request, so a client
   that stalls is force-disconnected instead of pinning a thread forever. A
   single mechanism is used for both transports, keeping them identical: closing
   the socket/channel from the watchdog thread unblocks the in-progress read
   (TCP `read()` throws `SocketException`; an NIO channel throws
   `AsynchronousCloseException`), which the handler already treats as
   end-of-connection.

2. **A `Semaphore` connection cap** is acquired in each accept loop *before* a
   handler is started; if no permit is free the new socket is closed immediately,
   and the permit is released exactly once when the connection ends.

### Before

```java
// KmsServer — unbounded executor, nothing else
this.executor = Executors.newVirtualThreadPerTaskExecutor();
```

```java
// TcpTransport.acceptLoop — accept and run, no cap, no timeout
socket = serverSocket.accept();
final String peer = "tcp:" + socket.getRemoteSocketAddress();
executor.execute(factory.create(socket.getInputStream(), socket.getOutputStream(), peer, socket));
```

```java
// ConnectionHandler — blocks in readLine() with no deadline
private byte[] readNext(final BoundedLineReader reader) throws IOException {
  return reader.readLine();
}
```

### After

```java
// KmsServer — a connection cap and a watchdog scheduler
this.connectionLimiter = new Semaphore(config.maxConnections());
this.idleWatchdog = new ScheduledThreadPoolExecutor(1, daemonThreadFactory);
this.idleWatchdog.setRemoveOnCancelPolicy(true); // purge the cancelled timeout of every served request
```

```java
// TcpTransport.acceptLoop — acquire a permit or reject; release if hand-off fails
socket = serverSocket.accept();
if (!connectionLimiter.tryAcquire()) {
  LOG.log(Level.WARNING, () -> "connection limit reached; rejecting " + socket.getRemoteSocketAddress());
  closeQuietly(socket);
  continue;
}
try {
  final String peer = "tcp:" + socket.getRemoteSocketAddress();
  executor.execute(factory.create(socket.getInputStream(), socket.getOutputStream(), peer, socket,
      connectionLimiter::release));
} catch (final IOException | RuntimeException e) {
  connectionLimiter.release(); // acquired above, but the handler never took ownership
  closeQuietly(socket);
}
```

```java
// ConnectionHandler — each read is bounded by the idle watchdog;
//                     the permit (onClose) is released exactly once when the loop ends
private byte[] readNext(final BoundedLineReader reader) throws IOException {
  final ScheduledFuture<?> timeout =
      idleWatchdog.schedule(this::closeForIdleTimeout, idleTimeoutMillis, TimeUnit.MILLISECONDS);
  try {
    return reader.readLine();
  } finally {
    timeout.cancel(false); // a request arrived in time → cancel the pending close
  }
}

private void closeForIdleTimeout() {
  LOG.log(Level.DEBUG, "closing {0}: idle timeout", peer);
  close(); // unblocks the blocked read with an IOException
}
// run() ... finally { close(); onClose.run(); }   // onClose == connectionLimiter::release
```

(The Unix transport got the identical permit acquire/release; both transports now
share the same watchdog via `ConnectionHandlerFactory`.)

## Why the fix works

- The **idle-timeout watchdog** converts the open-ended `readLine()` wait into a
  bounded one. Slowloris depends on holding a connection open while sending almost
  nothing; once a stalled connection is force-closed after the timeout, the cost
  of holding a slot is capped and the attack can no longer accumulate pinned
  connections. Scheduling-then-cancelling one task per request is cheap, and
  `setRemoveOnCancelPolicy(true)` keeps the watchdog queue from accumulating the
  cancelled timeout of every served request.
- The **connection-cap semaphore** turns an unbounded resource (threads / fds /
  heap) into a fixed one. Flooding can still fill the available slots, but it can
  no longer grow memory and descriptor use without limit or crash the process;
  slots free as connections finish or time out, so the server degrades and
  recovers instead of falling over. Together they bound *both* dimensions an
  attacker controls — how many connections, and how long each lasts.

## Tests

`server/src/test/java/.../ServerHardeningTest.java` boots a real server on an
ephemeral port and asserts that (a) an idle raw connection is closed around the
configured timeout, (b) a connection beyond the cap is closed immediately, and
(c) a freed slot accepts a later connection. `ServerConfigTest` covers the new
flags, their environment variables, and rejection of non-positive values.
