# wg-embed: an embeddable WireGuard-Go client

This module allows you to embed a WireGuard client into your Go application for easy tunnel setup.

Uses the Go userspace implementation of WireGuard by default, and optionally the Linux kernel module if available.

Supported OSes:
  - Linux

## Interface names

`NewWithOpts` refuses a name that is already taken and returns an error wrapping
`ErrInterfaceExists`. That usually means a previous run was killed before it could
remove its interface - for example with host networking, where the interface
survives the process. wg-embed never removes such an interface itself, since the
name may belong to something else on the host; delete it with
`ip link delete <name>` if nothing else uses it.

## Routes

A peer's allowed IPs say what the peer may send - they do not make the kernel
send anything there. For peers inside the interface's own subnet that makes no
difference, since the interface's addresses come with a route each. A network
*behind* a peer - a site, a subnet router - needs a route of its own, which is
what `wg-quick` does with `Table = auto`.

Set `ManageRoutes` in `Options` and wg-embed keeps those routes in line with the
peers: it adds one for every allowed network the interface's addresses do not
already reach, and removes it again with the peer.

```go
wg, err := wgembed.NewWithOpts(wgembed.Options{
    InterfaceName:     "wg0",
    AllowKernelModule: true,
    ManageRoutes:      true,
})
```

Two things it deliberately does not do:

- **It never removes a route it did not add.** One set up by hand, or from a
  lifecycle command, stays - including when a peer wants the same network.
- **It never adds a default route.** `wg-quick` does for a client that tunnels
  everything; on a server that would send its own traffic, the tunnel's own
  packets included, into the tunnel.

Linux only - elsewhere the option does nothing.

## Tests

Tests that create interfaces need `CAP_NET_ADMIN` and `/dev/net/tun`. Run them in a
container, as CI does:

```bash
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD":/src -w /src -e WGEMBED_TEST_NETADMIN=1 \
  golang:1.27-bookworm go test -race ./...
```
