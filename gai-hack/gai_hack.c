#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include "../type4.h"
typedef int (*real_gai_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
#define GAIHACK_INITIALIZED 0x100000000ULL
static uint64_t gaihack_flags = 0;
static char *sni_proxy_host = NULL;
static char *sm_dirname = NULL;
static char *my_logfile = NULL;
static real_gai_t gai_func_real = NULL;
struct my_domain {
	uint64_t dot_positions;
	char domain_name[256];
	char null_guard[8];
};
static int do_parse_domain(const char *name, struct my_domain *d) {
	const char *namei = name;
	int starts_with_dot = 0;
	uint64_t dot_positions = -1ULL;
	int cur_pos = 0;
#define APPEND_CHAR(ch) do { if (cur_pos >= 255) goto fail; d->domain_name[cur_pos++] = (ch); } while (0)
while (namei[0] == '.') {
		namei++;
		starts_with_dot = 1;
	}
	if (namei[0] == 0) {
		if (starts_with_dot) goto is_root;
		return 1;
	}
	while (1) {
		int c = namei[0];
		if (c == 0) break;
		switch (c) {
			case '0'...'9':
			case 'a'...'z':
			case '-':
			case '_':
				APPEND_CHAR(c);
				break;
			case 'A'...'Z':
				APPEND_CHAR(c - 'A' + 'a');
				break;
			case '.':
				/* a...long.test.www.example.com. */
				/*     |    |    |   |       |   */
				while (namei[0] == '.') namei++;
				if (namei[0] == 0) goto breakout;
				APPEND_CHAR('.');
				dot_positions = (dot_positions << 8) | (cur_pos & 0xff);
				continue;
			default:
				goto fail;

		}
		namei++;
		continue;
breakout:
		break;
	}
	d->dot_positions = __builtin_bswap64(dot_positions);
	return 0;
fail:
	return 1;
is_root:
	d->dot_positions = -1ULL;
	d->domain_name[0] = '.';
	d->domain_name[1] = 0;
	return 0;
}
static int check_name(int dir_fd, const char *name, char target_name[260]) {
	int file_fd = openat(dir_fd, name, O_CLOEXEC|O_RDONLY|O_NOCTTY, 0);
	if (file_fd < 0) {
		if (errno == ENOENT) goto check_symlink;
		return 1;
	}
	ssize_t read_result = read(file_fd, target_name, 258);
	close(file_fd);
	if (read_result <= 0) {
		return 1;
	}
	if ((target_name[0] == 'X') && (target_name[1] == ',')) {
		char *newline = memchr(&target_name[2], '\n', 256);
		if (newline) {
			*newline = 0;
			return 0;
		}
		return 1;
	}
	return 1;
check_symlink:
	ssize_t rl_result = readlinkat(dir_fd, name, target_name, 258);
	if (rl_result < 0) {
		switch (errno) {
			case ENOENT:
			case EINVAL:
				return 2;
		}
		return 1;
	}
	if ((target_name[0] == 'X') && (target_name[1] == ',')) return 0;
	return 2;
}
static int search_static_map(char ident[2], int dir_fd, struct my_domain *d, int *localhost_was_checked, char target_name[260]) {
	uint64_t cur_dot_pos = d->dot_positions;
	memset(&target_name[0], 0, 260);
	char tempname[260] = {0};
	ssize_t f = snprintf(tempname, 258, "%c,%s", ident[0], d->domain_name);
	if (f <= 0) return 1;
	switch (check_name(dir_fd, tempname, target_name)) {
		case 0:
		return 0;
		case 1:
		return 1;
	}
	for (int i = 0; i < 8; i++) {
		memset(&target_name[0], 0, 260);
		memset(&tempname[0], 0, 260);
		uint8_t dot_offset = cur_dot_pos & 0xff;
		cur_dot_pos = cur_dot_pos >> 8;
		if (dot_offset == 0) continue;
		if (dot_offset == 255) continue;
		char *domain_name_wildcard = &d->domain_name[dot_offset];
		if (strcmp(domain_name_wildcard, "localhost") == 0) *localhost_was_checked |= 1;
		f = snprintf(tempname, 258, "%c,%s", ident[1], domain_name_wildcard);
		if (f <= 0) return 1;
		switch (check_name(dir_fd, tempname, target_name)) {
			case 0:
				return 0;
			case 1:
				return 1;
			/* 2 == continue */
		}
	}
	memset(&target_name[0], 0, 260);
	char wildcard_name[4];
	wildcard_name[0] = ident[1];
	wildcard_name[1] = ',';
	wildcard_name[2] = 'R';
	wildcard_name[3] = 0;
	switch (check_name(dir_fd, wildcard_name, target_name)) {
		case 0:
			return 0;
		case 1:
			return 1;
	}
	return 2;
}
static int gai_hack(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res, real_gai_t real_gai) {
	/* don't intercept IPv4 literals. IPv6 literals would fail the domain parsing anyway. */
	*res = NULL;
	struct addrinfo hints_local = {.ai_flags = AI_V4MAPPED};
	struct my_domain domain_r = {0};
	if (hints) memcpy(&hints_local, hints, sizeof(struct addrinfo));
	hints_local.ai_flags &= ~AI_ADDRCONFIG;
	if (!node) goto do_real_gai;
	struct in_addr dummy = {0};
	if (inet_aton(node, &dummy)) goto do_real_gai;
	if (do_parse_domain(node, &domain_r)) goto do_real_gai;
	int is_localhost = 0;
	char target_name[260];
	int static_map_dir_fd = open(sm_dirname, O_RDONLY|O_PATH|O_DIRECTORY|O_CLOEXEC);
	if (static_map_dir_fd < 0) return EAI_AGAIN;
	int sm_hi_result = search_static_map("hH", static_map_dir_fd, &domain_r, &is_localhost, target_name);
	close(static_map_dir_fd); static_map_dir_fd = -1;
	if (sm_hi_result == 0) {
		return real_gai(&target_name[2], service, &hints_local, res);
	}
	if (sm_hi_result == 1) {
		return EAI_AGAIN;
	}
	struct addrinfo *ires = NULL;
	int real_result = real_gai(node, service, &hints_local, &ires);
	switch (real_result) {
		case EAI_ADDRFAMILY:
		case EAI_FAIL:
		case EAI_AGAIN:
		case EAI_NODATA:
		case EAI_NONAME:
			goto do_lo;
		case 0: /* TODO: ignore ipv4 or ipv6 */
			*res = ires;
			return 0;
		default:
			return real_result;
	}
do_lo:
	static_map_dir_fd = open(sm_dirname, O_RDONLY|O_PATH|O_DIRECTORY|O_CLOEXEC);
	if (static_map_dir_fd < 0) return EAI_AGAIN;
	sm_hi_result = search_static_map("lL", static_map_dir_fd, &domain_r, &is_localhost, target_name);
	close(static_map_dir_fd); static_map_dir_fd = -1;
	if (sm_hi_result == 0) {
		return real_gai(&target_name[2], service, &hints_local, res);
	}
	if (sm_hi_result == 1) return EAI_AGAIN;
	if (strcmp(domain_r.domain_name, "localhost") == 0) return EAI_AGAIN;
	if (is_localhost) return EAI_AGAIN;
	if (my_logfile) {
		int logfile_fd = open(my_logfile, O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC, 0600);
		if (logfile_fd >= 0) {
			char buf[300] = {0};
			ssize_t n = snprintf(buf, 298, "sni_proxy_needed_for \"%s\"\n", domain_r.domain_name);
			if (n > 0) {
				if (n >= 298) n = 298;
				write(logfile_fd, buf, n);
			}
			close(logfile_fd);
		}
	}
	if (sni_proxy_host) {
		return real_gai(sni_proxy_host, service, &hints_local, res);
	}
	return EAI_AGAIN;
do_real_gai:
	return real_gai(node, service, &hints_local, res);
}
__attribute__((visibility("default")))
int getaddrinfo /* _override */(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	if (gaihack_flags & GAIHACK_INITIALIZED) {
		return gai_hack(node, service, hints, res, gai_func_real);
	}
	return gai_func_real(node, service, hints, res);
}
void gai_hack_init(int do_init, struct urtp_functions *functable) {
	real_gai_t real_gai_func = functable->_dlsym(RTLD_NEXT, "getaddrinfo");
	if (!real_gai_func) {
		fprintf(stderr, "Could not get real getaddrinfo(): %s\n", functable->_dlerror());
		abort();
	}
	gai_func_real = real_gai_func;
	if (!do_init) return;
	char *sm_dirname_ = getenv("PJTL_GAIHACK_STATICDIR");
	if (sm_dirname_) {
		char *sm_dirname_a = strdup(sm_dirname_);
		if (!sm_dirname_a) abort();
		sm_dirname = sm_dirname_a;
	}
	sm_dirname_ = getenv("PJTL_GAIHACK_SNI_PROXY");
	if (sm_dirname_) {
		char *sm_dirname_a = strdup(sm_dirname_);
		if (!sm_dirname_a) abort();
		sni_proxy_host = sm_dirname_a;
	}
	sm_dirname_ = getenv("PJTL_GAIHACK_LOGFILE");
	if (sm_dirname_) {
		char *sm_dirname_a = strdup(sm_dirname_);
		if (!sm_dirname_a) abort();
		my_logfile = sm_dirname_a;
	}
	sm_dirname_ = getenv("PJTL_GAIHACK_FLAGS");
	if (sm_dirname_) {
		gaihack_flags = strtoull(sm_dirname_, NULL, 0);
	}
	gaihack_flags |= GAIHACK_INITIALIZED;
}
