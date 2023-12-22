all: liburelay-tproxy.so

liburelay-tproxy.so: preload.o subnet-masks.o type4.o
	$(CC) -pie -pthread -shared -o $@ $^ -ldl
%.o: %.c
	$(CC) -fPIC -fstack-protector-strong -fvisibility=hidden -c -o $@ $<
clean:
	rm -f liburelay-tproxy.so *.o
.PHONY: all clean
