CC=gcc
JSON_FLAGS=$(shell pkg-config --cflags json-c)
NDPI_READER=src/ndpiReader.c
NDPI_MAIN=src/lib/ndpi_main.c
GLIB_FLAGS=$(shell pkg-config --cflags glib-2.0)
GLIB_LIBS=$(shell pkg-config --libs glib-2.0)
LIBS= -ljson-c -pthread -lslog -lm -lpcap $(JSON_FLAGS) $(GLIB_FLAGS) -I/src/include
DEPS = src/include/

dmz: ndpiReader.o ndpi_main.o ahocorasick.o  node.o sort.o tcp_udp.o dmz_module.o
	$(CC)  -o  dmz ndpi_main.o ndpiReader.o  ahocorasick.o  node.o sort.o  tcp_udp.o dmz_module.o $(LIBS) $(GLIB_LIBS)
ndpiReader.o: $(NDPI_READER)
	$(CC) -c $(NDPI_READER) $(LIBS)
ndpi_main.o:  $(NDPI_MAIN) src/include/ndpi_protocols.h
	$(CC) -c  $(NDPI_MAIN) src/lib/third_party/include/ahocorasick.h $(LIBS)
ahocorasick.o:  src/third_party/src/ahocorasick.c
	$(CC) -c  src/third_party/src/ahocorasick.c  $(LIBS)
node.o: src/lib/third_party/src/node.c
	$(CC) -c src/lib/third_party/src/node.c  $(LIBS)
sort.o: src/lib/third_party/src/sort.c
	$(CC) -c src/lib/third_party/src/sort.c $(LIBS)
tcp_udp.o: src/lib/protocols/tcp_udp.c
	$(CC) -c src/lib/protocols/tcp_udp.c $(LIBS)
dmz_module.o: src/dmz_module.c
	$(CC) -c  src/dmz_module.c $(LIBS) 
clean:
	rm *.o
	rm dmz
