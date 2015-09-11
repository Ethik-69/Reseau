#! /usr/bin/python
# -*- coding:utf-8 -*-
#http://null-byte.wonderhowto.com/how-to/sploit-make-python-port-scanner-0161074/
from socket import *
import sys, time, optparse
from datetime import datetime

def scan_host(host, port, r_code = 1):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        code = s.connect_ex((host, port))
        if code == 0:
            r_code = code
        s.close()
    except Exception as e:
        pass
    return r_code

def main():
    parser = optparse.OptionParser("usage %prog " + "-i <Target ip> -M <Port max - Default : 5000> -m <port min - Default : 1>")
    parser.add_option('-i', dest='host', type='string', help='Target ip')
    parser.add_option('-M', dest='max_port', type='int', help='Port max')
    parser.add_option('-m', dest='min_port', type='int', help='Port min')
    (options, arg) = parser.parse_args()
    if (options.host == None):
        print(parser.usage)
        exit(0)
    elif (options.max_port == None) | (options.min_port == None):
        host = options.host
        max_port = 5000
        min_port = 1
    else:
        try:
            host = options.host
            max_port = options.max_port
            min_port = options.min_port
        except Exception as e:
            print(e)
            exit(0)

    hostip = gethostbyname(host)
    print("\n[*] Host : %s IP : %s" % (host, hostip))
    print("[*] Scanning Started At %s...\n" % (time.strftime("%H:%M:%S")))
    start_time = datetime.now()

    for port in range(min_port, max_port):
        try:
            response = scan_host(host, port)
            if response == 0:
                print("[*] Port %d: Open" % (port))
        except Exception as e:
            pass

    stop_time = datetime.now()
    total_time_duration = stop_time - start_time
    print("\n[*] Scanning Finished At %s ..." % (time.strftime("%H:%M:%S")))
    print("[*] Scanning Duration : %s ..." % (total_time_duration))

if __name__=='__main__':
    main()