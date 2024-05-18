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
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include "type4.h"
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
struct type3_data {
	uint8_t ipv6_addr[16];
	uint8_t bindtodevice[16];
	uint8_t bind_addr[16];
	uint32_t flags;
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
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_shutdown_func)(int, int) = NULL;
static ssize_t (*real_sendmsg_func)(int, const struct msghdr *, int) = NULL;
static struct data_header my_local_header;
static struct data_header *actual_data_header = NULL;
static size_t actual_data_header_len = 0;
static uint64_t local_flags = 0;

#ifdef URTP_FORCE_UNVERSIONED_SYMBOLS
void *dlsym_func(void *handle, const char *symbol_name);
char *dlerror_func(void);
int fstat_func(int fd, struct stat *st);
__asm__(
".irp func, dlerror, dlsym, fstat\n"
".symver \\func\\()_func,\\func\\()@\n"
".endr\n"
);
#else
#define dlsym_func dlsym
#define dlerror_func dlerror
#define fstat_func fstat
#endif

#define LOCAL_FLAG_SHUTDOWN_HACK 0x10000
#define LOCAL_FLAG_FASTOPEN_HACK 0x20000
#define LOCAL_FLAG_GETSOCKNAME_HACK 0x40000
#define LOCAL_FLAG_INIT_GAIHACK 0x80000
__attribute__((visibility("default")))
int getsockname(int fd, struct sockaddr *sa, socklen_t *len) {
	if (local_flags & LOCAL_FLAG_GETSOCKNAME_HACK) {
		int oldlen = *len;
		if (oldlen < 0) {
			errno = EINVAL;
			return -1;
		}
		socklen_t newlen = oldlen;
		if (real_getsockname(fd, sa, &newlen)) return -1;
		if ((oldlen >= 2) && (newlen == 2) && (sa->sa_family == AF_UNIX)) {
			struct sockaddr_in6 dummy = {.sin6_family = AF_INET6};
			if (oldlen >= sizeof(dummy)) oldlen = sizeof(dummy);
			memcpy(sa, &dummy, oldlen);
			*len = sizeof(dummy);
		} else {
			*len = newlen;
		}
		return 0;
	}
	return real_getsockname(fd, sa, len);
}
__attribute__((visibility("default")))
int getpeername(int fd, struct sockaddr *sa, socklen_t *len) {
	if (local_flags & LOCAL_FLAG_GETSOCKNAME_HACK) {
		int oldlen = *len;
		if (oldlen < 0) {
			errno = EINVAL;
			return -1;
		}
		socklen_t newlen = oldlen;
		if (real_getpeername(fd, sa, &newlen)) return -1;
		if ((oldlen >= 2) && (newlen >= 2) && (sa->sa_family == AF_UNIX)) {
			struct sockaddr_in6 dummy = {.sin6_family = AF_INET6};
			if (oldlen >= sizeof(dummy)) oldlen = sizeof(dummy);
			memcpy(sa, &dummy, oldlen);
			*len = sizeof(dummy);
		} else {
			*len = newlen;
		}
		return 0;
	}
	return real_getpeername(fd, sa, len);
}
__attribute__((visibility("default")))
int shutdown(int s, int which) {
	if (local_flags & LOCAL_FLAG_SHUTDOWN_HACK) {
		if (which == SHUT_RD) {
			int d = 0;
			int dlen = sizeof(int);
			if (getsockopt(s, SOL_SOCKET, SO_DOMAIN, &d, &dlen)) goto real_shutdown;
			if (d == AF_UNIX) {
				which = SHUT_RDWR;
			}
		}
	}
real_shutdown:
	return real_shutdown_func(s, which);
}
static int apply_t3_data(int fd, struct type3_data *data, int sock_domain) {
	uint32_t dev_len = strnlen(data->bindtodevice, 16);
	if (dev_len) {
		char b2d_safe[17] = {0};
		memcpy(b2d_safe, data->bindtodevice, dev_len);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, b2d_safe, dev_len+1)) return -1;
	}
	return 0;
}

static int get_tproxy_socket(const struct data_header *header, const struct data_header *header_safe, size_t header_total_size, struct sockaddr_in6 *sockaddr, struct type3_data *t3_data) {
	uint32_t a[4];
	memcpy(a, &sockaddr->sin6_addr, 16);
	int found_i = -1;
	int matched_mask = 128;
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
		matched_mask = mask;
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
	const char *data_start_offset = (const char *) &header->entries[header_safe->nr_subnet_entries];
	uint64_t data_offset = data_start_offset - ((char *) header);
	uint64_t data_start = data_offset + entry.offset;
	uint64_t data_end = data_start + entry.length;
	if (data_end > (uint64_t) header_total_size) {
		return -1;
	}
	unsigned char domain_result[140] = {0};
	size_t addl_hlen = 0;
	struct type5_data data_e = {.version = 1, .flags = TYPE5_FLAG_KEEP_OUTER_PORT};
	switch (entry.type) {
		case 0:
			return -2;
			break;
		case 5:
			if (entry.length < sizeof(struct type5_data)) return -1;
			memcpy(&data_e, &data_start_offset[entry.offset], sizeof(data_e));
			if (data_e.authority_selector.version == 1) {
				if (get_domain((uint8_t *) &sockaddr->sin6_addr, &data_e.authority_selector, &domain_result[3])) {
					domain_result[0] = 2;
					domain_result[1] = 0;
					domain_result[2] = strnlen(&domain_result[3], 128);
					addl_hlen += domain_result[2];
					addl_hlen += 3;
					entry.offset += sizeof(struct type5_data);
					entry.length -= sizeof(struct type5_data);
					goto c4_as_2;
				}
				return -1;
			} else {
				goto c4_as_2;
			}
		case 4:
			if (entry.length < sizeof(struct type4_data)) return -1;
			memcpy(&data_e.authority_selector, &data_start_offset[entry.offset], sizeof(data_e.authority_selector));
			if (get_domain((uint8_t *) &sockaddr->sin6_addr, &data_e.authority_selector, &domain_result[3])) {
				domain_result[0] = 2;
				domain_result[1] = 0;
				domain_result[2] = strnlen(&domain_result[3], 128);
				addl_hlen += domain_result[2];
				addl_hlen += 3;
				data_e.outer_ip_mask = 128; /* outer_ip{,_mask} == ::/128 sets outer_ip = 0 (::) */
				entry.offset += sizeof(struct type4_data);
				entry.length -= sizeof(struct type4_data);
				goto c4_as_2;
			}
			return -1;
		case 1:
			send_proxy_protocol = 0;
			/* fallthrough */
		case 2:
c4_as_2:;
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
			if (real_connect(s, (struct sockaddr *) &resultant, offsetof(struct sockaddr_un, sun_path) + length)) {
				close(s);
				return -1;
			}
			if (send_proxy_protocol) {
				struct pp2_header header2 = {0};
				memcpy(header2.magic, "\r\n\r\n\0\r\nQUIT\n", 12);
				header2.version = 0x21;
				header2.type = 0x21;
				size_t total_length = sizeof(header2) + addl_hlen;
				header2.length = htons(total_length - offsetof(struct pp2_header, data));
				struct iovec iovs[2] = {{&header2, sizeof(header2)}, {domain_result, addl_hlen}};
				if (apply_t5_data_header(sockaddr, &data_e, &header2)) {
					close(s);
					return -1;
				}
				if (writev(s, iovs, 2) != total_length) {
					close(s);
					return -1;
				}
			}
			return s;
			break;
		case 3:
			if (entry.length < sizeof(struct in6_addr)) return -1;
			struct in6_addr new_addr;
			memcpy(&new_addr, &data_start_offset[entry.offset], sizeof(struct in6_addr));
			uint32_t m[4];
			memcpy(m, subnet_mask_data[matched_mask], 16);
			new_addr.s6_addr32[0] = (m[0] & new_addr.s6_addr32[0]) | ((~m[0]) & sockaddr->sin6_addr.s6_addr32[0]);
			new_addr.s6_addr32[1] = (m[1] & new_addr.s6_addr32[1]) | ((~m[1]) & sockaddr->sin6_addr.s6_addr32[1]);
			new_addr.s6_addr32[2] = (m[2] & new_addr.s6_addr32[2]) | ((~m[2]) & sockaddr->sin6_addr.s6_addr32[2]);
			new_addr.s6_addr32[3] = (m[3] & new_addr.s6_addr32[3]) | ((~m[3]) & sockaddr->sin6_addr.s6_addr32[3]);
			memcpy(&sockaddr->sin6_addr, &new_addr, sizeof(struct in6_addr));
			if (t3_data) {
				uint32_t length = entry.length;
				if (length > sizeof(struct type3_data)) length = sizeof(struct type3_data);
				memcpy(t3_data, &data_start_offset[entry.offset], length);
			}
			return -3;
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
			struct type3_data t3_data = {0};
			int fflags_orig = fcntl(fd, F_GETFL, 0);
			if (fflags_orig < 0) goto do_real_connect;
			int fdflags_orig = fcntl(fd, F_GETFD, 0);
			if (fdflags_orig < 0) goto do_real_connect;
			int new_s = get_tproxy_socket(actual_data_header, &my_local_header, actual_data_header_len, &the_sockaddr, &t3_data);
			if (new_s == -2) {
				goto do_real_connect;
			}
			int connect_einprogress = 0;
			if (new_s == -3) { /* Translation mode. the_sockaddr has been updated to the new translated IPv6 address. */
				domain_size = sizeof(int);
				if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_size)) {
					goto fail_news;
				}
				switch (domain) {
					case AF_INET:
						/* If we're translating to ::ffff:0:0 we can just connect to the corresponding IPv4 */
						if (IN6_IS_ADDR_V4MAPPED(&the_sockaddr.sin6_addr)) {
							struct sockaddr_in ipv4;
							ipv4.sin_family = AF_INET;
							ipv4.sin_port = the_sockaddr.sin6_port;
							ipv4.sin_addr.s_addr = the_sockaddr.sin6_addr.s6_addr32[3];
							if (apply_t3_data(fd, &t3_data, AF_INET)) goto fail_news;
							errno = saved_errno;
							return real_connect(fd, (struct sockaddr *) &ipv4, sizeof(ipv4));
						}
						/* Otherwise we need to create an IPv6 socket and replace the original socket */
						new_s = socket(AF_INET6, SOCK_CLOEXEC|SOCK_STREAM|((fflags_orig & O_NONBLOCK) ? SOCK_NONBLOCK : 0), IPPROTO_TCP);
						if (new_s < 0) goto fail_news;
						if (apply_t3_data(new_s, &t3_data, AF_INET6)) goto fail_news;
						int rv = real_connect(new_s, (struct sockaddr *) &the_sockaddr, sizeof(the_sockaddr));
						if (rv == 0) {
							break;
						} else if ((rv == -1) && (errno == EINPROGRESS)) {
							connect_einprogress = 1;
							break;
						}
						goto fail_news;
						break;
					case AF_INET6:
						/* We can connect with either IPv4 or IPv6. */
						if (apply_t3_data(fd, &t3_data, AF_INET6)) goto fail_news;
						errno = saved_errno;
						return real_connect(fd, (struct sockaddr *) &the_sockaddr, sizeof(the_sockaddr));
						break;
					default:
						goto do_real_connect;
				}
			}
			int nonblocking = !!(fflags_orig & O_NONBLOCK);
			if (ioctl(new_s, FIONBIO, &nonblocking)) {
				goto fail_news;
			}
			if (dup3(new_s, fd, (fdflags_orig & FD_CLOEXEC) ? O_CLOEXEC : 0) != fd) {
				goto fail_news;
			}
			close(new_s);
			if (connect_einprogress) {
				errno = EINPROGRESS;
				return -1;
			}
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
	struct urtp_functions functable = {._dlsym = dlsym_func, ._dlerror = dlerror_func, ._fstat = abort};
	char *datafile_name = getenv("URELAY_TPROXY_FILE");
	if (datafile_name) {
		int datafile_fd = open(datafile_name, O_RDONLY|O_NOCTTY|O_CLOEXEC);
		if (datafile_fd < 0) {
			fprintf(stderr, "tproxy-preload: Failed to open %s: %s\n", datafile_name, strerror(errno));
			abort();
			return;
		}
		off_t file_size = lseek(datafile_fd, 0, SEEK_END);
		if (file_size < sizeof(my_local_header)) {
			fprintf(stderr, "tproxy-preload: File empty or less than minimum size\n");
			abort();
			return;
		}
		void *datafile_mmap = mmap(NULL, file_size, PROT_READ, MAP_SHARED, datafile_fd, 0);
		if (datafile_mmap == MAP_FAILED) {
			fprintf(stderr, "tproxy-preload: Failed to mmap %s: %s\n", datafile_name, strerror(errno));
			abort();
			return;
		}
		close(datafile_fd);
		actual_data_header = datafile_mmap;
		actual_data_header_len = file_size;
		if (actual_data_header_len < sizeof(my_local_header)) abort();
		memcpy(&my_local_header, actual_data_header, sizeof(my_local_header));
		if (my_local_header.magic != htonl(0xf200a01fU)) {
			fprintf(stderr, "tproxy-preload: bad magic number in %s\n", datafile_name);
			abort();
			return;
		}
		my_local_header.nr_subnet_entries = ntohs(my_local_header.nr_subnet_entries);
		if (actual_data_header_len < (offsetof(struct data_header, entries) + (my_local_header.nr_subnet_entries * sizeof(struct data_entry)))) abort();
	}
	void *connect_symbol = dlsym_func(RTLD_NEXT, "connect");
	if (connect_symbol == NULL) abort();
	real_connect = connect_symbol;
	void *sendmsg_symbol = dlsym_func(RTLD_NEXT, "sendmsg");
	if (sendmsg_symbol == NULL) abort();
	real_sendmsg_func = sendmsg_symbol;
	void *getsockname_symbol = dlsym_func(RTLD_NEXT, "getsockname");
	if (getsockname_symbol == NULL) abort();
	real_getsockname = getsockname_symbol;
	void *getpeername_symbol = dlsym_func(RTLD_NEXT, "getpeername");
	if (getpeername_symbol == NULL) abort();
	real_getpeername = getpeername_symbol;
	void *shutdown_symbol = dlsym_func(RTLD_NEXT, "shutdown");
	if (!shutdown_symbol) {
		abort();
	}
	real_shutdown_func = shutdown_symbol;
	char *local_flags_s = getenv("URELAY_TPROXY_LOCAL_FLAGS");
	if (local_flags_s) local_flags = strtoull(local_flags_s, NULL, 0);
	gai_hack_init(!!(local_flags & LOCAL_FLAG_INIT_GAIHACK), &functable);
	local_flags_s = getenv("URELAY_TPROXY_IDX_FILES");
	if (local_flags_s) {
		if (!init_idxf_array(local_flags_s, &functable)) abort();
	}
}
__attribute__((visibility("default")))
ssize_t sendmsg(int fd, const struct msghdr *mh, int flags) {
	if (local_flags & LOCAL_FLAG_FASTOPEN_HACK) {
		if (flags & MSG_FASTOPEN) {
			errno = EPIPE;
			return -1;
		}
	}
	return real_sendmsg_func(fd, mh, flags);
}
__attribute__((visibility("default")))
ssize_t sendto(int fd, const void *data, size_t len, int flags, const struct sockaddr *a, socklen_t al) {
	struct iovec iov = {.iov_base = (void *) data, .iov_len = len};
	struct msghdr mh = {.msg_name = (void *) a, .msg_namelen = al, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0};
	return sendmsg(fd, &mh, flags);
}
