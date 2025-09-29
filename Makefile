CC ?= gcc
CFLAGS ?= -Wall -std=c99 -fPIC -O3

TRACING ?= 0

ifeq ($(TRACING), 1)
	CFLAGS += -DTRACING
endif

LIBCRYPTO_OBJECTS = \
	src/libcrypto.o

LIBSSL_OBJECTS = \
	src/libssl.o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: libcrypto.so.1.0.0 libssl.so.1.0.0

clean:
	rm -rf libcrypto.so.1.0.0 $(LIBCRYPTO_OBJECTS) $(LIBSSL_OBJECTS) libssl.so.1.0.0


libcrypto.so.1.0.0: $(LIBCRYPTO_OBJECTS)
	$(CC) -shared -o $@ $<

libssl.so.1.0.0: $(LIBSSL_OBJECTS)
	$(CC) -shared -o $@ $<

