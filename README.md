# tarweb

io-uring & ktls based webserver serving files from a tar file.

* No memory allocations
* No syscalls (`io_uring`)

https://github.com/ThomasHabets/tarweb

## Prerequisites

You need at least kernel 6.7, with `IO_URING` and `TLS` enabled. 6.7 introduced
io-uring enabled `setsockopt`, which is required.

If `CONFIG_TLS=m` then the `tls` kernel module needs to be loaded. At least on
my system, it doesn't automatically load on demand.

```
$ grep ^CONFIG_TLS= /boot/config-$(uname -r)
CONFIG_TLS=m
$ lsmod | grep ^tls
$ sudo modprobe tls
$ tlmod | grep ^tls
tls                   151552  0
```

To load it automatically on every boot, add it to `/etc/modules`:

```
$ echo tls | sudo tee -a /etc/modules
```

## Example use

Create a tar file with your whole site. There should be an `index.html` in the
root of the tar file.

Alternatively, provide `tarweb` with a prefix to strip.

```
$ tar tf site1.tar | head
blog.habets.se/
blog.habets.se/2015/
blog.habets.se/2015/11/
blog.habets.se/2015/11/Building-pov-ray-on-raspberry-pi.html
blog.habets.se/2015/11/How-I-made-my-custom-keyboard-layout-on-Linux-and-Windows.html
blog.habets.se/2015/03/
blog.habets.se/2015/03/How-to-boot-an-encrypted-system-safely.html
blog.habets.se/2015/03/Raytracing-Quake-demos.html
blog.habets.se/2015/03/My-mechanical-keyboard.html
blog.habets.se/2015/03/Scraping-data-from-a-BT-home-hub-5.html
$ tarweb \
  --listen '[::]:8081' \
  --tls-key privkey.pem \
  --tls-cert fullchain.pem \
  --prefix blog.habets.se/ \
  site1.tar
```

## Benchmarking

oha is a nice tool.

```
cargo install oha
oha https://localhost:8080/
```

Flamegraph

On VisionFive 2:

```
$ sudo sysctl -w kernel.perf_event_paranoid=-1
$ cargo install flamegraph
$ mkdir ~/bin; cat > ~/bin/myperf
set -ueo pipefail
echo "$@" >> wrapcmd
CMD="$1"
shift
if [[ $CMD = "record" ]]; then
        exec perf "$CMD" -e task-clock "$@"
fi
exec perf "$CMD" "$@"
^D
$ chmod +x ~/bin/myperf
$ PERF=$HOME/bin/myperf cargo flamegraph
```

On the VF2 for an ~24kB file, 1-2% of CPU is userspace. 75% of userspace CPU is
the RSA signing operation.
In kernel space it's all AES and TCP.

On a beefier machine, though still a laptop, `parse_request` is 35% of
userspace. `Archive::get_ofs` is 7%. Still, this laptop could probably saturate
a 10Gbps link at least, with small requests.

## Future work

* use `writev` to reduce queue roundtrips.
* `TCP_CORK`?

## Random notes

* There's no `sendfile()` in io-uring, but while there's `slice()` which could
  be used to implement `sendfile()` while bouncing on a pipe, there's no
  `pipe(2)` in io-uring either, so that'd force a syscall per connection. But I
  guess a pool of pipes can be pre-created?
  * I think I'll just wait for `sendfile()` to be supported natively in
    io-uring.
* Maybe it'd be possible to use io-uring buffers for read operations, but then
  either it'd require copying from the fixed buffer to the connection buffer, or
  parse request from a non-contiguous buffer (all the while holding on to the
  buffer, and there can only be 65536 of them).


## HTTP/3 with routable connection IDs

`tarweb-h3` can issue QUIC-LB connection IDs so `sni-router-h3` can forward
replacement CIDs and client address migrations. This is opt-in: without any
`--quic-lb-*` flags, the existing 16-byte worker CIDs and behavior are unchanged.

Create a shared AES-128 key file and restrict access to it:

```sh
umask 077
openssl rand -hex 16 > quic-lb.key
```

Configure the router with the same key, configuration ID, and backend ID (see
sni-router's QUIC-LB configuration). Then start the backend:

```sh
tarweb-h3 --listen '[::1]:8443' --tls-cert cert.pem --tls-key key.pem \
    --quic-lb-key-file quic-lb.key --quic-lb-server-id 123 \
    --quic-lb-config-id 0 site.tar
```

The key file must contain 32 hexadecimal characters, with optional surrounding
whitespace. Server IDs are decimal unsigned 32-bit integers. Configuration IDs
are 0 through 6 and default to 0 when QUIC-LB is enabled. The key-file and server-ID
flags must be provided together; a configuration ID alone is an error.

The implementation supports the 17-byte, single-pass AES-128 encoding from
`draft-ietf-quic-load-balancers-22`. The encrypted block begins with a four-byte
backend ID; its twelve-byte nonce also carries private worker-routing and
validation data. Other QUIC-LB encodings are not supported. Quinn handles QUIC
packet authentication and path validation without any dependency modifications.

Provision the router's decoder before enabling a new server configuration.
During key rotation, retain both old and new configurations in the router until
connections using the old configuration have drained. Do not reassign a backend
ID within an active configuration. Tarweb loads its configuration at startup;
restarting tarweb does not preserve QUIC connections.

Routable paths authorize access to a configured backend without another SNI ACL
check. Migrated paths receive fresh idle/global lifetime timers at the router;
they do not retain the original SNI rule's connection lifetime limit. Use this
mode only with that routing policy in mind.

To run the cross-repository rotation and migration test after building both
binaries:

```sh
SNI_ROUTER_H3_BIN=../sni-router/target/debug/sni-router-h3 \
    cargo test --test h3_quic_lb -- --ignored --nocapture
```
