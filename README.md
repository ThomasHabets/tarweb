## TODO Improvements

* io_submit to batch up syscalls?
* send(MSG_ZEROCOPY): https://lwn.net/Articles/726917/
* SOCKMAP?
https://www.gnu.org/software/tar/manual/html_node/Standard.html

TODO:
* Enable EPOLLET & EPOLLONESHOT?
* Short read/write means no need to try again
* use event.data.ptr to find connection, not look up by fd
* EPOLLRDHUP?
* EPOLLHUP? (don't bother reading from closed connection)
* Keepalive connection
* For short files, do writev() from mmap(), for large files, do sendfile()
* ktls
* request timeout

