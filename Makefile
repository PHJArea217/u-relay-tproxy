CFLAGS := -O2 -g -fstack-protector-strong
ifeq ($(PARACONTAINERIZATION),1)
# older libc versions didn't have dl* functions in libc.so.6, so force linking to libdl
CFLAGS_E := -DURTP_FORCE_UNVERSIONED_SYMBOLS=1 -Wl,-z,relro,-z,now,--push-state,--as-needed -ldl -Wl,--pop-state
else
CFLAGS_E := -Wl,-z,relro,-z,now -ldl
endif
all: liburelay-tproxy.so

liburelay-tproxy.so: preload.o subnet-masks.o type4.o type5.o gai-hack/gai_hack.o
	$(CC) -pie -pthread -shared -o $@ $^ $(CFLAGS_E)
%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_E) -fPIC -fvisibility=hidden -c -o $@ $<
clean:
	rm -f liburelay-tproxy.so *.o gai-hack/*.o
.PHONY: all clean
