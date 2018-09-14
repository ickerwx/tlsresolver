# tlsresolver
Enumerate host names by parsing TLS certificates (CN and SAN)

```
$ ./tlsresolver.py -h
usage: tlsresolver.py [-h] (-i IPADDRESSES | -f FILE) [-p PORTS] [-t THREADS]

Retrieve hostnames from TLS certificates

optional arguments:
  -h, --help            show this help message and exit
  -i IPADDRESSES, --ip IPADDRESSES
                        comma-separated list of IP addresses (e.g.
                        127.0.0.1,fe80::)
  -f FILE, --file FILE  file containing host:port1,port2,... lines, one line
                        per host
  -p PORTS, --ports PORTS
                        comma-separated list of ports (default:
                        443,636,993,995,8443)
  -t THREADS, --threads THREADS
                        set number of threads (default: 5)
```

You can pass multiple IP addresses and ports by separating them with a comma:

```
-i 127.0.0.1,127.0.0.2 -p 1,2,3,4,5
```

The default number of threads is 5, this seems to be more than enough on a LAN.

## Input file format

```
$ cat examplefile
1.1.1.1
2.2.2.2:22
3.3.3.3:33,333
4.4.4.4:44,444,4444
```

If you don't specify ports in the file, then the program will use either the default ports or whatever you specify with `-p`.

## Example run

```
$ ./tlsresolver.py -p 443 -i 93.184.216.34
93.184.216.34: ['www.example.org', 'example.com', 'example.edu', 'example.net', 'example.org', 'www.example.com', 'www.example.edu', 'www.example.net']
```
