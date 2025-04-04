# rtweb

"Real-time" webserver experiment.

* No memory allocations
* No syscalls (`io_uring`)

## Kernel

* Need kernel 6.7 for setsockopt
