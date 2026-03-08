# Lunatik Tests

Integration tests for lunatik kernel modules. Output follows the
[KTAP](https://docs.kernel.org/dev-tools/ktap.html) format (TAP version 13).

## Requirements

- Lunatik modules loaded: `sudo lunatik load`
- Lua scripts installed: `sudo make tests_install`
- Root privileges
- `ping(1)`, `nc(1)`, `curl(1)`

## Running

```
sudo bash tests/run.sh
```

Individual suites:

```
sudo bash tests/netfilter/run.sh
```

Individual tests:

```
sudo bash tests/netfilter/drop.sh
sudo bash tests/netfilter/rst.sh
sudo bash tests/netfilter/prerouting.sh
sudo bash tests/netfilter/mark.sh
sudo bash tests/netfilter/gc.sh
sudo bash tests/thread/spawn.sh
```

## Thread tests

### spawn

Regression test for `lunatik spawn` and graceful thread termination.

1. After `lunatik spawn`, the script appears in `lunatik list`.
2. After `lunatik stop`, the script is absent from `lunatik list`.
3. No kernel errors (BUG, WARNING, scheduling while atomic) in dmesg.

## Netfilter tests

### drop

Hook at `LOCAL_OUT` drops UDP packets to port 5555.
Exercises `nf.action.DROP` and `nf.action.ACCEPT`.

1. UDP packet to loopback:5555 is delivered before the hook is loaded.
2. UDP packet to loopback:5555 is not delivered while the hook is loaded.
3. UDP packet to loopback:5555 is delivered after the hook is unloaded.

### rst

Hook at `LOCAL_IN` intercepts TCP SYN to port 7777, truncates the payload
(`skb:resize`), recalculates checksums (`skb:checksum`), and injects a
RST+ACK back to the sender (`skb:forward`).

1. TCP connection to loopback:7777 succeeds before the hook is loaded.
2. TCP connection to loopback:7777 is rejected with RST while the hook is loaded (curl exit 7).
3. TCP connection to loopback:7777 succeeds after the hook is unloaded.

### prerouting

Hook at `PRE_ROUTING` drops ICMP Echo Requests on loopback.
Exercises the `PRE_ROUTING` hook point.

1. `ping 127.0.0.1` succeeds before the hook is loaded.
2. `ping 127.0.0.1` fails while the hook is loaded.
3. `ping 127.0.0.1` succeeds after the hook is unloaded.

### mark

Two hooks at `LOCAL_OUT`, one with `mark=0` (fires for unmarked packets)
and one with `mark=1` (skipped for unmarked packets). Exercises the `mark`
field in `nf.register`.

1. Hook with `mark=0` drops UDP to port 5560; packet is not delivered.
2. Hook with `mark=1` is skipped for unmarked UDP to port 5561; packet is delivered.
3. UDP to port 5560 is delivered after the hooks are unloaded.
4. UDP to port 5561 is delivered after the hooks are unloaded.

### gc

Regression test for GC running under spinlock in `lunatik_monitor`
(commit `2e841609`). A hook allocates 50 Lua tables per packet; sending
200 packets builds GC pressure. If GC finalizers run inside the spinlock,
the kernel reports "scheduling while atomic".

1. After 200 packets through the hook, no Lua errors appear in dmesg.
2. No "scheduling while atomic" appears in dmesg.

