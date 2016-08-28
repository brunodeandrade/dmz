# Instalação DMZ

1. Caso esteja em sistemas Debian-like, execute o comando:
	$ sudo make install

2. Em seguida, execute 
	$ sudo ./dmz -i eth0.

2. Caso negativo, instale as seguintes bibliotecas:
	$ sudo apt-get install libjson0 libjson0-dev libglib2.0-dev libpcap0.8-dev

	* Instale o slog: 
		$ git clone https://github.com/kala13x/slog.git
	        $ cd slog/src
	        $ make
	        $ sudo make install

3. Em seguida, execute o comando:
	$ make

4. E logo após:
	$ sudo ./dmz -i eth0

5. Em caso de dúvidas: brunounbgama@gmail.com 

6. Seja feliz. :)



