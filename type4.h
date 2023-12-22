#include <stdint.h>
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
int get_domain(uint8_t ip[16], struct type4_data *data, char domain_result[128]);
int init_idxf_array(const char *config_s);
