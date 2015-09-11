#! /usr/bin/python
# -*- coding:utf-8 -*-
import urllib.request

url_list = [
"http://upload.wikimedia.org/wikipedia/commons/7/72/IPhone_Internals.jpg",
"http://upload.wikimedia.org/wikipedia/en/2/26/Common_face_of_one_euro_coin.jpg",]

for url in url_list:
    with urllib.request.urlopen(url) as response:
        print("Status:", response.status)
        _, _, filename = response.geturl().rpartition("/")
        print("Writing:", filename)
        with open(filename, "wb") as image:
            image.write(response.read())