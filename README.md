# Instalação DMZ

### OBS: Toda a instalação foi feita na pasta /opt, sugere-se manter o padrão.
### OBS2: Para realizar a instalação do DMZ, é necessário acesso a internet ou solicitar os arquivos para a equipe DMZ.

Toda a instalação do DMZ é feita como root, então antes de começa-la execute o comando:
```bash
su
```

Antes de instalar o DMZ, instale as seguintes bibliotecas:
```bash
# sudo apt-get install libjson0 libjson0-dev libglib2.0-dev git autoconf libtool libpcap-dev
```

Entre na pasta /opt
```bash
# cd /opt
```

Instale o slog: 
```bash
# git clone https://github.com/kala13x/slog.git
# cd slog/src
# make
# make install
```

Baixe o código-fonte da nDPI no repositório oficial (https://github.com/ntop/nDPI.git);
```bash
# cd /opt
# git clone https://github.com/ntop/nDPI.git
```

Entre na pasta clonada da nDPI 
```bash
# cd nDPI
```
Assegure-se que o código está na versão do commit com a hash, usando o comando:
```bash
# git checkout e9f7df081fe5a405a462a85218ecf66e858ea99a -b dmz
```
Ao digitar ```git log```, o primeiro resultado deverá ser:
```bash
# git log

e9f7df081fe5a405a462a85218ecf66e858ea99a
Merge: d0b83a7 e7cb3d3
Author: Luca <deri@ntop.org>
Date:   Thu Jan 21 16:33:20 2016 +0100
Merge branch 'dev' of https://github.com/ntop/nDPI into dev
```

Para sair da tela de log, pressione ```q```.

Ainda na pasta nDPI/ execute os comandos:
```bash
# ./autogen.sh
# ./configure
```
Tais comandos devem ser concluídos sem erros.


Após a instalação da nDPI, volte a pasta /opt
```bash
# cd /opt
```

Clone o repositório do DMZ
```bash
# git clone https://gitlab.com/saltar/dmz-module.git
```

Copie todos os arquivos da pasta dmz-module para a pasta nDPI/example/ 
```bash
# cp -r /opt/dmz-module/. /opt/nDPI/example/
```

No arquivo Makefile dentro da pasta /opt/nDPI/example, procure a flag CFLAGS substitua tudo, exceto o '-g' e o '-lm' pelo seguinte comando:
```bash
$(shell pkg-config --cflags --libs json glib-2.0)
```

O resultado final deve ficar igual à imagem:
![Imgur](http://i.imgur.com/i1fkfzc.png)

E substitua a flag LDFLAGS pelo comando:
```bash
$(shell pkg-config --libs json)
```
O resultado final deve ficar igual à imagem:
![Imgur](http://i.imgur.com/UI4Gmry.png)

Execute o make na pasta nDPI/
```bash
# cd /opt/nDPI
# make
```

Execute um make clean na pasta nDPI/example, e em seguida um make.
```bash
# cd /opt/nDPI/example
# make clean
# make
```
Na pasta nDPI/example, execute a aplicação com o comando:
```bash
# cd /opt/nDPI/example
# ./ndpiReader -i eth0
```

![Imgur](http://i.imgur.com/fLXemNS.png)

# Teste da Aplicação
Agora iremos executar os testes a fim de verificar o funcionamento correto da aplicadação.

Primeiramente, ela deve ser parada. Pode-se fazer isto utilizando o Ctrl + c.

Temos a necessidade de iniciar um serviço para receber pacotes e então, realizarmos os
testes. Para tanto, iremos utilizar o apache2, para deixar disponível o acesso HTTP
na porta 80.

```bash
$ sudo apt-get install apache2
```

## Instalação
Agora iremos baixar um script de testes.

Para isso, utilize uma máquina diferente da máquina que possui o DMZ em execução.
Essa máquina será a atacante e iremos enviar pacotes a partir dela.

Digite o seguinte comando:
```bash
$ git clone https://github.com/TiagoAssuncao/suite-attacks-dos
```
Assim, iremos entrar na pasta e instalar as dependências.

```bash
$ cd suite-attacks-dos

$ sudo apt-get install hping3
```

Para compilar o código, basta apenas executar o comando make.
```bash
$ make
```

Agora iremos a partir desta máquina(atacante), enviar pacotes para o alvo
(servidor com o apache2 em funcionamento).

O IP do servidor tem que ser analisado
no momento do ataque, pois, este pode ser alterado confirme a rede. Neste nosso
caso de teste, o ip do servidor é 192.168.20.91. Assim, iremos iniciar a aplicação
enviando pacotes para este IP. Antes de começarmos, vá no servidor e inicie novamente
a aplicação DMZ.

```bash
$ cd /opt/nDPI/example
$ sudo ./ndpiReader -i eth0
```

O script de testes irá mandar um fluxo baixo de pacotes para o servidor durante
450 segundos. Este fluxo irá setar o aprendizado do DMZ com esta quantidade de pacotes. Após,
iremos aumentar o fluxo em 5 vezes durante 300 segundos. Isso irá gerar um alerta
de Warning durante 4 polls e no quinto, será sinalizado o ataque. Enfim, vamos ao
ataque. Rode este comando na máquina atacante:

```bash
$ sudo ./run -s 192.168.20.91
```

A saída esperada são confirmações dos pacotes enviados. Com o fluxo de um por segundo:

```bash
len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1189 win=29200 rtt=4.3 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1190 win=29200 rtt=8.3 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1191 win=29200 rtt=4.3 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1192 win=29200 rtt=4.3 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1193 win=29200 rtt=4.3 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1194 win=29200 rtt=11.7 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1195 win=29200 rtt=23.4 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1196 win=29200 rtt=3.2 ms

len=44 ip=192.168.20.91 ttl=63 DF id=0 sport=80 flags=SA seq=1197 win=29200 rtt=3.3 ms
...
```

Após os 450 segundos, a saída esperada será a mesma, porém, com o fluxo de 5 pacotes
por segundo.

A saída esperada no servidor onde se encontra o DMZ para os warings e para o ataque
é a seguinte:

![OutputLog](https://raw.githubusercontent.com/wiki/TiagoAssuncao/suite-attacks-dos/atc.png)
