# Bounty-HTB

## NMAP

Esta maquina solo tiene el puerto 80 abierto.

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/4d99534a-d8d7-4b37-8450-fee111059940)

## Dirbuster y WFUZZ

Para esta maquina ya nos dimos cuenta que nos enfrentamos a un ISS 7.5 buscamos archivos .aspx, .asp, .config.

```
dirbuster -u http://10.129.1.185/ -t 200 -l /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -r dirout.ext -e php,txt,html,asp,aspx,config


```
Siempre que estes probando algo creo que es bueno ver hacktricks.

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services

Se encontro una pagina trasfer.aspx

![image](https://github.com/gecr07/Bounty-HTB/assets/63270579/39bea836-ef1f-41c3-a8c0-303c2e772704)


Siempre que tenemos este tipo de cosas hay que probar que extenciones permiten las que nos permitirian ejecutar comandos son .asp, aspx y .config ( esta yo no sabia). Otra ruta que se encontro es:

> http://10.129.18.176/UploadedFiles
































































































