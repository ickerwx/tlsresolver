#!/usr/bin/env python3

import argparse
import sys
import ipaddress as ipa
from threading import Thread, Lock
import queue
import time

# TODO: [ ] input file with ip:p1,p2,p3 lines
# TODO: [ ] import nmap XML or greppable


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
            return


def main():
    args = parse_args()
    try:
        ipaddresses = [ipa.ip_address(i) for i in args.ipaddresses.split(',')]
        ports = [int(p) for p in args.ports.split(',')]
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        sys.exit(1)

    # all targets are written to a queue. Each thread will pick the next available target from the queue.
    target_queue = queue.Queue()
    for ip in ipaddresses:
        target_queue.put((ip, ports))

    # create args.threads threads, start them ans add them to the list
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
                # queue is empty and all threads are done, we can safly exit
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
