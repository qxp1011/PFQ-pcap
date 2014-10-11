PFQ + libpcap 
=============

Introduction
------------

PFQ is a network monitoring framework designed for the Linux operating system 
that allows efficient packet capturing, in-kernel functional processing and packet 
steering across sockets.

This version of pcap library is extended to natively support PFQ, thus allowing 
legacy applications to exploit the capture acceleration of PFQ and at the 
same time, to take advantage of Q-Lang computations to filter and dispatch packets
across pcap sockets.

The pcap library interface is *unchanged*. Additional data (e.g. pfq group) is passed 
to the library as environment variables, while sniffing from multiple devices is enabled 
by specifying their name in colon-separated fashion.

The greatest benefits are achieved with the cooperation of pfqd, a user-space daemon used
to manage groups and in-kernel computations.


Features
--------

* 10-Gbit Line-rate (14,8Mpps) with tcpdump.
* Parallel session of legacy applications through Q-lang computations.
* Socket groups allow for concurrent monitoring of multiple multi-threaded pcap applications.
* Fully compliant with Q-Lang and pfqd.

Authors
-------

Nicola Bonelli <nicola@pfq.io>  
Giacomo Volpi <volpi.gia@gmail.com>


HomePages
---------

PFQ home-page is [www.pfq.io][1]. 


[1]: http://www.pfq.io
