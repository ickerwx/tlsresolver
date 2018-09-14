# tlsresolver
Enumerate host names by parsing TLS certificates (CN and SAN)

```
$ ./tlsresolver.py -h
usage: tlsresolver.py [-h] -i IPADDRESSES -p PORTS [-t THREADS]

Retrieve hostnames from TLS certificates

optional arguments:
  -h, --help            show this help message and exit
  -i IPADDRESSES, --ip IPADDRESSES
                        comma-separated list of IP addresses (e.g.
                        127.0.0.1,fe80::)
  -p PORTS, --ports PORTS
                        comma-separated list of ports
  -t THREADS, --threads THREADS
                        set number of threads
```

You can pass multiple IP addresses and ports by separating them with a comma:

```
-i 127.0.0.1,127.0.0.2 -p 1,2,3,4,5
```

The default number of threads is 5, this seems to be more than enough on a LAN.
