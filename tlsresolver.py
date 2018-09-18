#!/usr/bin/env python3

import argparse
import sys
import ipaddress as ipa
import threading
import queue
import time
import socket
import ssl

# TODO: import nmap XML or greppable
# TODO: implement actual support for IPv6
# TODO: pretty-print the results
# TODO: sqlite storage, then output data in different formats (csv, json)


def parse_args():
    parser = argparse.ArgumentParser(description='Retrieve hostnames from TLS certificates',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     argument_default=argparse.SUPPRESS)

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-i', '--ip', dest='ipaddresses',
                       help='comma-separated list of IP addresses (e.g. 127.0.0.1,fe80::)')
    group.add_argument('-f', '--file', dest='file',
                       help='file containing host:port1,port2,... lines, one line per host')
    parser.add_argument('-p', '--ports', dest='ports', help='comma-separated list of ports',
                        default='443,636,993,995,8443')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=5,
                        help='set number of threads')

    return parser.parse_args()


def scan_host(q):
    resolved = {}
    while not q.empty():
        try:
            ip, ports = q.get_nowait()
        except queue.Empty:
            break

        sslcontext = ssl.create_default_context()
        sslcontext.check_hostname = False

        names = []
        for port in ports:
            try:
                if type(ip) is ipa.IPv6Address:
                    s = sslcontext.wrap_socket(socket.socket(socket.AF_INET6))
                    # I had mixed success with IPv6, but on a my dual-stack system it seemed to work fine
                    s.connect((str(ip), port, 0, 0))
                else:
                    s = sslcontext.wrap_socket(socket.socket())
                    s.settimeout(1)
                    s.connect((str(ip), port))

                cert = s.getpeercert()
                if 'subject' in cert.keys():
                    for tup in cert['subject']:
                        for key, val in tup:
                            if key.lower() == 'commonname' and val.lower() not in names:
                                names.append(val.lower())

                if 'subjectAltName' in cert.keys():
                    for key, val in cert['subjectAltName']:
                        if key.lower() == 'dns' and val.lower() not in names:
                            names.append(val.lower())
            except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
                # something broke, or the port does not do TLS, we just skip it
                pass
        resolved[ip] = names
    for i in resolved.keys():
        print(str(i) + ": " + str(resolved[i]))


def main():
    # main() just creates -t threads, puts the targets in a queue and runs the threads.
    # then it just periodically checks if the queue is empty and if all threads are finished
    # if this happens, the program exits
    args = parse_args()

    # all targets are written to a queue. Each thread will pick the next available target from the queue.
    target_queue = queue.Queue()

    try:
        if 'ipaddresses' in args:
            ipaddresses = [ipa.ip_address(i) for i in args.ipaddresses.split(',')]
            ports = set([int(p) for p in args.ports.split(',')])  # convert list comprehension to set for unique values
            for ip in ipaddresses:
                # put (ip, ports) tuples into the queue. each thread will process the next available tuple
                target_queue.put((ip, ports))
        else:
            lines = [l.strip() for l in open(args.file, 'r').readlines()]
            for line in lines:
                if ':' in line:
                    ip, ports = line.split(':')
                else:
                    ip = line
                    ports = args.ports
                ip = ipa.ip_address(ip)
                ports = set([int(p) for p in ports.split(',')])  # convert list comprehension to set for unique values
                target_queue.put((ip, ports))
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        sys.exit(1)

    # create args.threads threads, start them and add them to the list
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=scan_host, args=(target_queue,))
        t.start()
        threads.append(t)

    while True:
        try:
            # periodically check if the queue still contains targets and if the threads are still running
            time.sleep(0.5)
            if target_queue.empty() and True not in [t.is_alive() for t in threads]:
                # queue is empty and all threads are done, we can safely exit
                sys.exit(0)

        except KeyboardInterrupt:
            # Ctrl+C was pressed: empty the queue and wait for the threads to finish
            # each thread will return once the queue is empty
            while not target_queue.empty():
                try:
                    target_queue.get(block=False)
                except queue.Empty:
                    pass
            sys.exit(0)


if __name__ == '__main__':
    main()
