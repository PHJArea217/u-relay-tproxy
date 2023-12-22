all: liburelay-tproxy.so

liburelay-tproxy.so: preload.o subnet-masks.o
	$(CC) -fPIC -pthread -shared -o $@ $^ -ldl
%.o: %.c
	$(CC) -fstack-protector-strong -fvisibility=hidden -c -o $@ $<
clean:
	rm -f liburelay-tproxy.so
.PHONY: all clean
