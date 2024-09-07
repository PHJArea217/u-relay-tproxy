#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
struct data_entry {
	uint8_t subnet_addr[16];
	uint8_t subnet_mask;
	uint8_t type;
	uint16_t length;
	uint32_t offset;
	uint8_t reserved[8];
};
struct data_header {
	uint32_t magic;
	uint16_t nr_subnet_entries;
	uint16_t total_length; /* 4096-byte units */
	uint32_t flags;
	uint32_t reserved;
	struct data_entry entries[0];
};
struct type3_data {
	uint8_t ipv6_addr[16];
	uint8_t bindtodevice[16];
	uint8_t bind_addr[16];
	uint32_t flags;
};
struct urtp_globals {
	void (*int16tonum)(uint16_t, char *);
	int (*real_connect)(int, const struct sockaddr *, socklen_t);
	int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
	int (*real_getpeername)(int, struct sockaddr *, socklen_t *);
	int (*real_shutdown_func)(int, int);
	ssize_t (*real_sendmsg_func)(int, const struct msghdr *, int);
	struct data_header my_local_header;
	struct data_header *actual_data_header;
	size_t actual_data_header_len;
	uint64_t local_flags;
};
struct urtp_t1_globals {
	void (*sockaddr_un_subst)(const struct sockaddr_in6 *, struct sockaddr_un *, uint32_t);
};
extern struct urtp_globals *urtp_preload_globals;
extern struct urtp_t1_globals *urtp_preload_t1_globals;
