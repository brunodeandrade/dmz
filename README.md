# Instalação DMZ

## OBS: Toda a instalação deve ser feita na pasta /opt

Antes de instalar o DMZ, instale as seguintes bibliotecas:
```bash
sudo apt-get install libjson0 libjson0-dev libglib2.0-dev git autoconf libtool libpcap-dev
```
Instale o slog: 
```bash
git clone https://github.com/kala13x/slog.git
cd slog/src
make
sudo make install
```

Baixe o código-fonte da nDPI no repositório oficial (https://github.com/ntop/nDPI.git);
```bash
git clone https://github.com/ntop/nDPI.git
```

Entre na pasta clonada da nDPI 
```bash
cd nDPI
```
Assegure-se que o código está na versão do commit com a hash, usando o comando:
```bash
git checkout e9f7df081fe5a405a462a85218ecf66e858ea99a -b dmz
```
Ao digitar ```git log```, o primeiro resultado deverá ser:
```bash
git log

e9f7df081fe5a405a462a85218ecf66e858ea99a
Merge: d0b83a7 e7cb3d3
Author: Luca <deri@ntop.org>
Date:   Thu Jan 21 16:33:20 2016 +0100
Merge branch 'dev' of https://github.com/ntop/nDPI into dev
```

Na pasta nDPI/ execute os comandos:
```bash
./autogen.sh
./configure
```

Após a instalação da nDPI, volte a pasta /opt

```bash
cd /opt
```

Clone o repositório do DMZ
```bash
git clone https://gitlab.com/saltar/dmz-module.git
```
Copie todos os arquivos da pasta dmz_module para a pasta nDPI/example/ 
```bash
cp -r . /opt/nDPI/example/
```

No arquivo Makefile dentro da pasta /opt/nDPI/example, procure a flag CFLAGS conforme mostra a imagem e substitua por tudo, exceto o '-g' e o '-lm' pelo seguinte comando:
```bash
$(shell pkg-config --cflags --libs json glib-2.0)
```
![Imgur](http://i.imgur.com/i1fkfzc.png)

E substitua a flag LDFLAGS pelo comando:
```bash
$(shell pkg-config --libs json)
```
![Imgur](http://i.imgur.com/Y0CUQTY.png)

Execute o make na pasta nDPI/
```bash
cd /opt/nDPI
make
```

Execute um make clean na pasta nDPI/example, e em seguida um make.
```bash
cd /opt/nDPI/example
make clean
make
```
Na pasta nDPI/example, execute a aplicação com o comando:
```bash
cd /opt/nDPI/example
sudo ./ndpiReader -i eth0
```

![Imgur](http://i.imgur.com/fLXemNS.png)
