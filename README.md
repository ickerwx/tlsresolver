# tlsresolver
Enumerate host names by parsing TLS certificates (CN and SAN)

```
$ ./tlsresolver.py -h
  -h, --help            show this help message and exit
  -i IPADDRESSES, --ip IPADDRESSES
                        comma-separated list of IP addresses or CIDR networks
                        (e.g. 127.0.0.1,fe80::,1.2.3.0/24)
  -f FILE, --file FILE  file containing host port1,port2,... lines, one line
                        per host (see README)
  -p PORTS, --ports PORTS
                        comma-separated list of ports (default:
                        443,636,993,995,8443)
  -t THREADS, --threads THREADS
                        set number of threads (default: 5)
  -to TIMEOUT, --timeout TIMEOUT
                        socket timeout (default: 1.0)
  -v, --verbose         Print empty results (default: False)
```

You can pass multiple IP addresses, networks and ports by separating them with a comma:

```
-i 127.0.0.1,127.0.0.2,127.1.2.0/24 -p 1,2,3,4,5
```

You can also query IPv6 addresses, and query a mix of IPv6 and IPv4 addresses. The default number of threads is 5, this seems to be more than enough on a LAN.

## Input file format

```
$ cat examplefile
1.1.1.1
2.2.2.2 22
3.3.3.3 33,333
4.4.4.4 44,444,4444
5.5.5.5/24
6.6.6.6/28 66,666,6666
```

Don't specify /32 as a subnet mask, this will not work.
If you don't specify ports in the file, then the program will use either the default ports or whatever you specify with `-p`.

## Example run

```
$ ./tlsresolver.py -p 443 -i 93.184.216.34,2606:2800:220:1:248:1893:25c8:1946
2606:2800:220:1:248:1893:25c8:1946: ['www.example.org', 'example.com', 'example.edu', 'example.net', 'example.org', 'www.example.com', 'www.example.edu', 'www.example.net']
93.184.216.34: ['www.example.org', 'example.com', 'example.edu', 'example.net', 'example.org', 'www.example.com', 'www.example.edu', 'www.example.net']
```
