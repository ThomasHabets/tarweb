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
* request timeout
* support headerless, where all headers are already pre-inserted into the tarfile
* verify that archive doesn't have sparse files
* content-type
* FDO

## Useful references
* https://youtu.be/8NSzkYSX5nY
* https://youtu.be/36qZYL5RlgY

## Memory allocations per request

### Full file request

* 4096 bytes request read buffer.
* 40 bytes for 5 output queue entries
  * status200
  * if applicable: keepalive header
  * if applicable: transfer encoding header
  * file-specific headers (namely content-length)
  * contents

### Range read

* 4096 bytes request read buffer.
* regex match_results parsing range header
* 48 bytes (should be enough) for range header
* output queue entries (see full request)
