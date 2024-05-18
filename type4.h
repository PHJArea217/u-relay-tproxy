#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
struct idxf_ent {
	uint32_t idx;
	uint32_t data_offset;
};
struct idxf_hdr {
	uint32_t magic;
	uint32_t nr_entries;
};
struct idx_file {
	uint32_t idx;
	uint32_t flags;
	void *base;
	size_t len;
};
#define IDXF_FLAGS_DIRECT_DOMAIN 1
struct type4_data {
	uint8_t version;
	uint8_t flags;
	uint8_t idx_shift;
	uint8_t ent_shift;
	uint32_t idx_mask;
	uint32_t ent_mask;
	uint32_t idx_offset;
	uint32_t ent_offset;
	uint32_t reserved[3];
};
struct type5_data {
	uint8_t version;
	uint8_t flags;
#define TYPE5_FLAG_KEEP_OUTER_PORT 0x1
#define TYPE5_FLAG_KEEP_INNER_PORT 0x2
#define TYPE5_FLAG_SEND_INNER 0x4
#define TYPE5_FLAG_SEND_OUTER_ALSO_AS_SRC 0x8
	uint8_t outer_ip_mask;
	uint8_t inner_ip_mask;
	uint16_t outer_port;
	uint16_t inner_port;
	uint32_t eflags;
	uint8_t outer_ip[16];
	uint8_t inner_ip[16];
	struct type4_data authority_selector;
} __attribute__((packed));
	// uint16_t flags2;
struct pp2_inner {
	uint32_t header_version; /* htonl(0xE0001B01) */
	uint16_t inner_port;
	uint8_t inner_ip[16];
	uint32_t info1;
	uint32_t info2;
} __attribute__((packed));
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
			struct pp2_inner inner;
		} ipv6;
		char other[216];
	} data;
};
int apply_t5_data_header(const struct sockaddr_in6 *in6, const struct type5_data *data, struct pp2_header *header);
int get_domain(uint8_t ip[16], struct type4_data *data, char domain_result[128]);
struct urtp_functions {
	void *(*_dlsym)(void *, const char *);
	char *(*_dlerror)(void);
	int (*_fstat)(int, struct stat *);
};
int init_idxf_array(const char *config_s, struct urtp_functions *functable);
void gai_hack_init(int do_init, struct urtp_functions *functable);
