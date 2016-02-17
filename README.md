# Instalação DMZ


- Antes de instalar o DMZ, instale as seguintes bibliotecas:
	$ sudo apt-get install libjson0 libjson0-dev libglib2.0-dev 
- Instale o slog: 
	$ git clone https://github.com/kala13x/slog.git
        $ cd slog/src
        $ make
        $ sudo make install
## DMZ

1. Baixe o código-fonte da nDPI no repositório oficial (https://github.com/ntop/nDPI.git);
2. Assegure-se que o código está na versão do commit com a hash:
	e9f7df081fe5a405a462a85218ecf66e858ea99a
	Merge: d0b83a7 e7cb3d3
	Author: Luca <deri@ntop.org>
	Date:   Thu Jan 21 16:33:20 2016 +0100
    Merge branch 'dev' of https://github.com/ntop/nDPI into dev

3. Na pasta nDPI/ execute os comandos:
	$ ./autogen.sh
	$ ./configure

4. Caso o ./configure dê erro, será necessário baixar as bibliotecas que faltam (o log mostrará quais bibliotecas necessitam ser baixadas).

5. Copie todos os arquivos da pasta dmz_module para a pasta nDPI/example/ (inclusive a pasta oculta .git).

6. Execute o comando:
	
	$ pkg-config --cflags --libs glib-2.0
	$ pkg-config --cflags --libs json	

7. Copie as flags que apareceram no console e coloque na variável CFLAGS do Makefile da pasta example/ (substitua as flags que já existem mantendo apenas o -g e -lm).

8. Execute o make na pasta nDPI/

9. Execute um make clean na pasta nDPI/example, e em seguida um make.

9. Na pasta nDPI/example, execute a aplicação com o comando:
	$ sudo ./ndpiReader -i eth0

10. Qualquer dúvida: brunounbgama@gmail.com ou (61)8191-5075(Whatsapp)
