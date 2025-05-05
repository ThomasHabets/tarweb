# tarweb

io-uring & ktls based webserver serving files from a tar file.

* No memory allocations
* No syscalls (`io_uring`)

## Prerequisites

Needs `CONFIG_TLS=y` or `=m` with the module loaded.

```
$ grep ^CONFIG_TLS= /boot/config-$(uname -r)
CONFIG_TLS=m
$ lsmod | grep ^tls
$ sudo modprobe tls
$ tlmod | grep ^tls
tls                   151552  0
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

## Kernel

* Need kernel 6.7 for setsockopt

## Future work

* Use io-uring buffers for read operations.
* use `writev` to reduce queue roundtrips.
* `TCP_CORK`?

## Random notes

* There's no `sendfile()` in io-uring, but while there's `slice()` which could
  be used to implement `sendfile()` while bouncing on a pipe, there's no
  `pipe(2)` in io-uring either, so that'd force a syscall per connection. But I
  guess a pool of pipes can be pre-created?
