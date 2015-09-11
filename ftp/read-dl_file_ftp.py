#! /usr/bin/python
# -*- coding:utf-8 -*-
import sys
import ftplib

def directory_list(host):
    connection = ftplib.FTP(host, user="anonymous")
    print("Welcome", connection.getwelcome())
    for name in connection.nlst():
        print(name)

def get(host, fullname):
    connection = ftplib.FTP(host, user="anonymous")
    print("Welcome", connection.getwelcome())
    size = connection.size(fullname)

    print("Getting", fullname, "size", size, "bytes")
    with open(fullname, "w") as output:
        connection.retrlines("RETR {0}".format(fullname), output.write)

host = "cdsarc.u-strasbg.fr"

directory_list(host)
get(host, "ls-lR.gz")