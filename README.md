# tarweb

io-uring & ktls based webserver serving files from a tar file.

* No memory allocations
* No syscalls (`io_uring`)

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
