#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
extern uint8_t subnet_mask_data[129][16];
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
struct pp2_header {
	uint8_t magic[12];
	uint8_t version;
	uint8_t type;
	uint16_t length;
	union {
		struct {
			uint8_t remote[16];
			uint8_t local[16];
			uint16_t remote_port;
			uint16_t local_port;
		} ipv6;
		char other[216];
	} data;
};
static void int16tonum(uint16_t n, char *num) {
	num[4] = '0' + (n % 10);
	n /= 10;
	num[3] = '0' + (n % 10);
	n /= 10;
	num[2] = '0' + (n % 10);
	n /= 10;
	num[1] = '0' + (n % 10);
	n /= 10;
	num[0] = '0' + (n % 10);
}
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static struct data_header my_local_header;
static struct data_header *actual_data_header = NULL;
static size_t actual_data_header_len = 0;
static int get_tproxy_socket(const struct data_header *header, const struct data_header *header_safe, size_t header_total_size, struct sockaddr_in6 *sockaddr) {
	uint32_t a[4];
	memcpy(a, &sockaddr->sin6_addr, 16);
	int found_i = -1;
	for (uint32_t i = 0; i < header_safe->nr_subnet_entries; i++) {
		const struct data_entry *entry = &header->entries[i];
		unsigned int mask = entry->subnet_mask;
		if (mask > 128) continue;
		uint32_t m[4];
		uint32_t v[4];
		memcpy(m, subnet_mask_data[mask], 16);
		memcpy(v, entry->subnet_addr, 16);
		for (int j = 0; j<4; j++) {
			if ((a[j] & m[j]) == v[j]) {
			} else {
				goto not_found;
			}
		}
		found_i = i;
		goto found;
not_found:
		;
	}
	return -2;
found:
	struct data_entry entry;
	memcpy(&entry, &header->entries[found_i], sizeof(struct data_entry));
	entry.offset = ntohl(entry.offset);
	entry.length = ntohs(entry.length);
	int send_proxy_protocol = 1;
	switch (entry.type) {
		case 1:
			send_proxy_protocol = 0;
			/* fallthrough */
		case 2:
			const char *data_start_offset = (const char *) &header->entries[header_safe->nr_subnet_entries];
			uint64_t data_offset = data_start_offset - ((char *) header);
			uint64_t data_start = data_offset + entry.offset;
			uint64_t data_end = data_start + entry.length;
			if (data_end > (uint64_t) header_total_size) {
				return -1;
			}
			struct sockaddr_un resultant = {AF_UNIX, {0}};
			uint32_t length = entry.length;
			if (length > (sizeof(resultant.sun_path) - 1)) length = sizeof(resultant.sun_path) - 1;
			memcpy(resultant.sun_path, &data_start_offset[entry.offset], length);
			char *subst_val = memmem(resultant.sun_path, length, "#//0_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[0]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//1_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[1]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//2_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[2]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//3_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[3]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//4_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[4]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//5_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[5]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//6_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[6]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//7_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_addr.s6_addr16[7]), subst_val);
			subst_val = memmem(resultant.sun_path, length, "#//P_", 5);
			if (subst_val) int16tonum(ntohs(sockaddr->sin6_port), subst_val);
			int s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
			if (s<0) return -1;
			if (connect(s, (struct sockaddr *) &resultant, offsetof(struct sockaddr_un, sun_path) + length)) {
				close(s);
				return -1;
			}
			if (send_proxy_protocol) {
				struct pp2_header header = {0};
				memcpy(header.magic, "\r\n\r\n\0\r\nQUIT\n", 12);
				header.version = 0x21;
				header.type = 0x21;
				header.length = htons(sizeof(header.data));
				memcpy(header.data.ipv6.local, &sockaddr->sin6_addr, sizeof(header.data.ipv6.local));
				header.data.ipv6.local_port = sockaddr->sin6_port;
				if (write(s, &header, sizeof(header)) != sizeof(header)) {
					close(s);
					return -1;
				}
			}
			return s;
			break;
	}
	return -1;
}
__attribute__((visibility("default")))
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
	int saved_errno = errno;
	errno = EINVAL;
	int domain = 0;
	socklen_t domain_size = sizeof(domain);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &domain, &domain_size)) goto do_real_connect;
	if (domain != SOCK_STREAM) goto do_real_connect;
	struct sockaddr_in6 the_sockaddr = {0};
	if ((len == sizeof(struct sockaddr_in)) && (addr->sa_family == AF_INET)) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *) addr;
		the_sockaddr.sin6_family = AF_INET6;
		the_sockaddr.sin6_addr.s6_addr16[5] = 0xffff;
		the_sockaddr.sin6_port = ipv4->sin_port;
		the_sockaddr.sin6_addr.s6_addr32[3] = ipv4->sin_addr.s_addr;
	} else if ((len == sizeof(struct sockaddr_in6)) && (addr->sa_family == AF_INET6)) {
		memcpy(&the_sockaddr, addr, sizeof(struct sockaddr_in6));
	}
	if (the_sockaddr.sin6_family == AF_INET6) {
		if (actual_data_header_len) {
			int fflags_orig = fcntl(fd, F_GETFL, 0);
			if (fflags_orig < 0) goto do_real_connect;
			int fdflags_orig = fcntl(fd, F_GETFD, 0);
			if (fdflags_orig < 0) goto do_real_connect;
			int new_s = get_tproxy_socket(actual_data_header, &my_local_header, actual_data_header_len, &the_sockaddr);
			if (new_s == -2) {
				goto do_real_connect;
			}
			int nonblocking = !!(fflags_orig & O_NONBLOCK);
			if (ioctl(new_s, FIONBIO, &nonblocking)) {
				goto fail_news;
			}
			if (dup3(new_s, fd, (fdflags_orig & FD_CLOEXEC) ? O_NONBLOCK : 0) != fd) {
				goto fail_news;
			}
			close(new_s);
			errno = saved_errno;
			return 0;
fail_news:
			close(new_s);
			if (errno == EBADF) errno = EINVAL;
			return -1;
		}
	}
do_real_connect:
	errno = saved_errno;
	int retval = real_connect(fd, addr, len);
	return retval;
}
__attribute__((constructor)) static void _init(void) {
	char *datafile_name = getenv("URELAY_TPROXY_FILE");
	if (datafile_name) {
		int datafile_fd = open(datafile_name, O_RDONLY|O_NOCTTY);
		if (datafile_fd < 0) {
			fprintf(stderr, "tproxy-preload: Failed to open %s: %s\n", datafile_name, strerror(errno));
			abort();
		}
		struct stat st = {0};
		if (fstat(datafile_fd, &st)) {
			abort();
		}
		void *datafile_mmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, datafile_fd, 0);
		if (datafile_mmap == MAP_FAILED) {
			fprintf(stderr, "tproxy-preload: Failed to mmap %s: %s\n", datafile_name, strerror(errno));
		}
		actual_data_header = datafile_mmap;
		actual_data_header_len = st.st_size;
		if (actual_data_header_len < sizeof(my_local_header)) abort();
		memcpy(&my_local_header, actual_data_header, sizeof(my_local_header));
		my_local_header.nr_subnet_entries = ntohs(my_local_header.nr_subnet_entries);
		if (actual_data_header_len < (offsetof(struct data_header, entries) + (my_local_header.nr_subnet_entries * sizeof(struct data_entry)))) abort();
	}
	void *connect_symbol = dlsym(RTLD_NEXT, "connect");
	if (connect_symbol == NULL) abort();
	real_connect = connect_symbol;
}

