# Linux Kernel TLS/DTLS Socket

*Note that the implementation is under heavy development. Use on your own risk!*

This kernel module introduces an ```AF_KTLS``` socket. ```AF_KTLS``` socket can
be used to transmit data over TLS 1.2 using TCP or DTLS 1.2 using UDP.
Currently, there is supported only AES GCM cipher.

The socket does data transmission, the handshake, re-handshaking and other
control messages have to be served by user space using appropriate libs such as
OpenSSL or Gnu TLS.  ```AF_KTLS``` socket appears to be faster especially for
transmitting files without user space (buffered-copy) interaction (using
```sendfile(2)``` or ```splice(2)```).

The socket uses RFC5288 proposed on Linux crypto mailing list by Dave
Watson from Facebook. The latest patches for rfc5288 are included in
this repo.  If you want to look at benchmarking scenarios or test your
use case speed impact, visit [AF_KTLS
tool](https://github.com/fridex/af_ktls-tool).

See [issues](http://github.com/fridex/af_ktls/issues) for awaiting
enhancements or bugs.

See also [AF_KTLS tool](https://github.com/fridex/af_ktls-tool), [AF_KTLS
visualize](https://github.com/fridex/af_ktls-visualize).


## Conference Talks

###  Fridolín Pokorný -  AF\_KTLS - TLS/DTLS Linux kernel module

Feb 5th 2017, Brussels, Belgium: FOSDEM 

 * [talk info](https://fosdem.org/2017/schedule/event/af_ktls/)
 * [slides](https://fosdem.org/2017/schedule/event/af_ktls/attachments/slides/1767/export/events/attachments/af_ktls/slides/1767/slides.)
 * [video](https://www.youtube.com/watch?v=CtxLPqqbiq0)

###  Fridolín Pokorný -  AF\_KTLS - TLS/DTLS Linux kernel module

Jan 21nd 2017, Brno, Czech republic: Devconf.cz 

 * [info](https://devconf.cz/)
 * [slides](https://fosdem.org/2017/schedule/event/af_ktls/attachments/slides/1767/export/events/attachments/af_ktls/slides/1767/slides.)
 * [video](https://www.youtube.com/watch?v=JkfvnRiVP50&t=5m50s)

###  Dave Watson - Kernel TLS (Transport Layer Security) Socket

Oct 5th 2016, Tokyo, Japan: Netdev 1.2

 * [talk info](http://netdevconf.org/1.2/session.html?dave-watson)
 * [slides](http://netdevconf.org/1.2/slides/oct5/05_davejwatson_tls_netdev12.pdf)
 * [video](https://www.youtube.com/watch?v=LbZu0D05Wko)
 * [paper](http://netdevconf.org/1.2/papers/ktls.pdf)

