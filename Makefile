all: liburelay-tproxy.so

liburelay-tproxy.so: preload.c subnet-masks.c
	$(CC) -fstack-protector-strong -fvisibility=hidden -fPIC -pthread -shared -o $@ $^ -ldl
clean:
	rm -f liburelay-tproxy.so
.PHONY: all clean
