all: liburelay-tproxy.so

liburelay-tproxy.so: preload.o subnet-masks.o type4.o type5.o gai-hack/gai_hack.o
	$(CC) -pie -pthread -shared -o $@ $^ -ldl
%.o: %.c
	$(CC) -fPIC -fstack-protector-strong -fvisibility=hidden -c -o $@ $<
clean:
	rm -f liburelay-tproxy.so *.o gai-hack/*.o
.PHONY: all clean
