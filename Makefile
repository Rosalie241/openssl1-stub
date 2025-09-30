CC := gcc
CFLAGS ?= -Wall -std=c99 -fPIC -O3
LDFLAGS ?= -s

TRACING ?= 0

ifeq ($(TRACING), 1)
	CFLAGS += -DTRACING
endif

LIBCRYPTO_OBJECTS = \
	src/libcrypto.o

LIBSSL_OBJECTS = \
	src/libssl.o

TARGETS = \
	libcrypto.so.1.0.0 \
	libssl.so.1.0.0

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(TARGETS)

clean:
	rm -rf $(TARGETS) $(LIBCRYPTO_OBJECTS) $(LIBSSL_OBJECTS)


libcrypto.so.1.0.0: $(LIBCRYPTO_OBJECTS)
	$(CC) $(LDFLAGS) -shared -o $@ $<

libssl.so.1.0.0: $(LIBSSL_OBJECTS)
	$(CC) $(LDFLAGS) -shared -o $@ $<

