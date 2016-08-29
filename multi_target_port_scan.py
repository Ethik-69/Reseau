#! /usr/bin/python
# -*- coding:utf-8 -*-
import sys, os, optparse, time
from datetime import datetime
import constant
from socket import *
from threading import *
import subprocess


class PortScan(object):
    def __init__(self):
        print('[*] Scanning Started At %s...\n' % time.strftime('%H:%M:%S'))
        self.start_time = datetime.now()

        self.screen_lock = Semaphore(value=1)
        setdefaulttimeout(1)
        self.host_prefix = self.current_local_ip()

        self.all_addr_scanned = {}
        self.default_ports = constant.default_ports

    def display_duration(self):
        print('')
        print('\n[*] Scan Finished At %s ...' % time.strftime('%H:%M:%S'))
        print('[*] Scanning Duration : %s ...' % (datetime.now() - self.start_time))

    def current_local_ip(self):
        """Get current local ip"""
        try:
            conn = socket(AF_INET, SOCK_DGRAM)
            conn.connect(('8.8.8.8', 80))
            current_ip = conn.getsockname()[0].split('.')
            conn.close()
            return ['.'.join(current_ip[:len(current_ip) - 1]) + '.']
        except:
            return ['192.168.0.', '192.168.1.']

    def main(self):
        for host_prefix in self.host_prefix:
            for host_suffix in range(1, 254):
                host_scanned = host_prefix + str(host_suffix)
                thread = Thread(target=self.port_scan, args=(host_scanned, self.default_ports))
                thread.start()

        while activeCount() > 1:
            pass

        self.display_result()
        self.display_duration()

    def display_result(self):
        """Display the result of all the scans"""
        for key in self.all_addr_scanned.keys():
            print('')
            print('--------------------------------------------------------------------------------------------------------')
            print('')
            print("[*] Name: %s Ip: %s" % (self.all_addr_scanned[key]['host_name'], self.all_addr_scanned[key]['host_ip']))
            if self.all_addr_scanned[key]['opened_ports'] != {}:
                print("---> Port open: ")
                for opened_port in self.all_addr_scanned[key]['opened_ports']:
                    port = self.all_addr_scanned[key]['opened_ports'][opened_port]['port_number']
                    process = self.all_addr_scanned[key]['opened_ports'][opened_port]['process'].replace('\n', '')
                    print("     - %s - %s" % (port, process))
            else:
                print('---> No port open')

    def conn_scan(self, host, port):
        """Specific Port scan"""
        try:
            conn = socket(AF_INET, SOCK_STREAM)
            conn.connect((host, port))
            # Gather information about process running on current tested port:
            conn.send('request\r\n')
            result = conn.recv(100)
            conn.close()
            return {'port_number': port, 'process': result}
        except:
            return

    def port_scan(self, host, ports):
        """Host scan"""
        self.screen_lock.acquire()
        result = subprocess.Popen(['ping', '-c', '1', '-W', '1', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = result.communicate()
        self.screen_lock.release()

        if result.returncode == 0:
            print('[*] %s is up, perform scan on it' % host)

            addr_info = dict()
            addr_info['opened_ports'] = dict()

            try:
                addr_info['host_ip'] = gethostbyname(host)
            except:
                return

            try:
                addr_info['host_name'] = gethostbyname(addr_info['host_ip'])
            except:
                pass

            if type(ports) == int:
                addr_info['opened_ports'] = self.conn_scan(host, int(ports))
            else:
                for port in ports:
                    port_info = self.conn_scan(host, int(port))
                    if port_info is not None:
                        addr_info['opened_ports'][port] = port_info

            self.screen_lock.acquire()
            self.all_addr_scanned[host] = addr_info
            print('')
            self.screen_lock.release()

        else:
            return

if __name__ == "__main__":
    port_scan = PortScan()
    port_scan.main()
