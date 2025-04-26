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

```
tarweb \
  --listen '[::]:8081' \
  --tls-key privkey.pem \
  --tls-cert fullchain.pem \
  site1.tar
```

## Kernel

* Need kernel 6.7 for setsockopt
