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

## Tests

Tests that create interfaces need `CAP_NET_ADMIN` and `/dev/net/tun`. Run them in a
container, as CI does:

```bash
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD":/src -w /src -e WGEMBED_TEST_NETADMIN=1 \
  golang:1.27-bookworm go test -race ./...
```
