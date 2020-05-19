CFLAGS=-I../libs/include -g
LDFLAGS=-lcrypto -L../libs/lib ../libs/lib/libpicotls-core.a ../libs/lib/libpicotls-openssl.a -lev -lmsgpackc
all: rt_client.o ftls.o
		cc $(LDFLAGS) -o rt_client rt_client.o ftls.o
