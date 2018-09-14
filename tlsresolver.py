#!/usr/bin/env python3

import argparse
import sys
import ipaddress as ipa
from threading import Thread, Lock
import queue
import time
import socket
import ssl

# TODO: input file with ip:p1,p2,p3 lines
# TODO: import nmap XML or greppable
# TODO: implement actual support for IPv6
# TODO: pretty-print the results
# TODO: sqlite storage, then output data in different formats (csv, json)


def parse_args():
    parser = argparse.ArgumentParser(description='Retrieve hostnames from TLS certificates')

    parser.add_argument('-i', '--ip', dest='ipaddresses',
                        help='comma-separated list of IP addresses (e.g. 127.0.0.1,fe80::)',
                        required=True)
    parser.add_argument('-p', '--ports', dest='ports', help='comma-separated list of ports', required=True)
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=5,
                        help='set number of threads')

    return parser.parse_args()


def scan_host(q):
    while not q.empty():
        try:
            ip, ports = q.get_nowait()
        except queue.Empty:
            break
        sslcontext = ssl._create_unverified_context()   # using ssl.create_default_context() makes the handshake fail
        sslcontext.check_hostname = False

        for port in ports:
            if type(ip) is ipa.IPv6Address:
                s = sslcontext.wrap_socket(socket.socket(socket.AF_INET6))
                # this does not work atm, I need to figure out what the tuple actually means
                s.connect((str(ip), port, 0, 0))
            else:
                s = sslcontext.wrap_socket(socket.socket())
                s.connect((str(ip), port))

            cert = s.getpeercert()
            names = []
            if 'subject' in cert.keys():
                for tup in cert['subject']:
                    for key, val in tup:
                        if key.lower() == 'commonname' and val.lower() not in names:
                            names.append(val.lower())

            if 'subjectAltName' in cert.keys():
                for key, val in cert['subjectAltName']:
                    if key.lower() == 'dns' and val.lower() not in names:
                        names.append(val.lower())

            mprint(str(ip) + ": " + str(names))


def mprint(msg):
    # this function will aquire a mutex before printing to avoid mixing thread output
    global_print_mutex.acquire()
    print(msg)
    global_print_mutex.release()


def main():
    # main() just creates -t threads, puts the targets in a queue and runs the threads.
    # then it just periodically checks if the queue is empty and if all threads are finished
    # if this happens, the program exits
    args = parse_args()
    try:
        ipaddresses = [ipa.ip_address(i) for i in args.ipaddresses.split(',')]
        ports = set([int(p) for p in args.ports.split(',')])  # convert list comprehension to set to get unique values
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        sys.exit(1)

    # all targets are written to a queue. Each thread will pick the next available target from the queue.
    target_queue = queue.Queue()
    for ip in ipaddresses:
        # put (ip, ports) tuples into the queue. each thread will process the next available tuple
        target_queue.put((ip, ports))

    # create args.threads threads, start them and add them to the list
    threads = []
    for i in range(args.threads):
        t = Thread(target=scan_host, args=(target_queue,))
        t.start()
        threads.append(t)

    while True:
        try:
            # periodically check if the queue still contains targets and if the threads are still running
            time.sleep(1)
            if target_queue.empty() and True not in [t.is_alive() for t in threads]:
                # queue is empty and all threads are done, we can safely exit
                sys.exit(0)

        except KeyboardInterrupt:
            # Ctrl+C was pressed: empty the queue and wait for the threads to finish
            while not target_queue.empty():
                try:
                    target_queue.get(block=False)
                except queue.Empty:
                    pass
            for t in threads:
                t.join()
            sys.exit(0)


global_print_mutex = Lock()
if __name__ == '__main__':
    main()
