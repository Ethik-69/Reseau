#! /usr/bin/python
# -*- coding:utf-8 -*-
import time
from socket import *
from datetime import datetime

def scan_host(host, port, r_code = 1):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.02)
        code = s.connect_ex((host, port))
        if code == 0:
            r_code = code
        s.close()
    except Exception as e:
        pass
    return r_code

def main():
    host = '192.168.1.'
    port = 80
    print('[*] Scanning Started At %s...\n' % (time.strftime('%H:%M:%S')))
    start_time = datetime.now()
    print('[*] Pc Online :\n')

    for ip in range(0, 255):
        try:
            host_scanner = host + str(ip)
            response = scan_host(host_scanner, port)
            if response == 0:
                print('[*] %s : Online' % (host_scanner))
        except Exception as e:
            pass

    stop_time = datetime.now()
    total_time_duration = stop_time - start_time
    print('\n[*] Scanning Finished At %s ...' % (time.strftime('%H:%M:%S')))
    print('[*] Scanning Duration : %s ...' % (total_time_duration))

if __name__=='__main__':
    main()