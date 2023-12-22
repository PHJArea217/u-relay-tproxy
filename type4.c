#include <endian.h>
#include <stdlib.h>
#include "type4.h"
uint32_t extract_ipv6_shift(uint64_t ip[2], uint8_t shift) {
	if (shift >= 64) return ip[0] >> (shift - 64);
	if (shift > 32) return (ip[0] << (64 - shift)) | (ip[1] >> shift);
	return ip[1] >> shift;
}
void extract_idx_ent(uint8_t ip[16], struct type4_data *data, uint32_t *idx_ent) {
	uint64_t ip_words[2] = {be64toh(*(uint64_t *)ip[0]), be64toh(*(uint64_t *)ip[1])};
	idx_ent[0] = be32toh(data->idx_offset) + (extract_ipv6_shift(ip_words, data->idx_shift) & be32toh(data->idx_mask));
	idx_ent[1] = be32toh(data->ent_offset) + (extract_ipv6_shift(ip_words, data->ent_shift) & be32toh(data->ent_mask));
}
struct idx_file *idxf_head = NULL;
size_t idxf_size = 0;
int compare_idxf(const void *a, const void *b) {
	const struct idx_file *af = (const struct idx_file *)a;
	const struct idx_file *bf = (const struct idx_file *)b;
	if (af->idx < bf->idx) return -1;
	if (af->idx > bf->idx) return 1;
	return 0;
}
struct idx_file *find_file(uint32_t idx) {
	struct idx_file dummy_idxf = {idx, 0, NULL, 0};
	return bsearch(idxf_head, sizeof(struct idx_file), idxf_size, compare_idxf);
}
int get_domain(uint8_t ip[16], struct type4_data *data, char domain_result[128]) {
	uint32_t idx_ent[2] = {0, 0};
	extract_idx_ent(ip, data, idx_ent);
	struct idx_file *f = find_file(idx_ent[0]);
	if (!f) return 0;
	if (f->flags & IDXF_FLAGS_DIRECT_DOMAIN) {
		memcpy(domain_result, f->base, (f->len < 128) ? f->len : 128);
		goto fill_domain;
	}
	volatile struct idxf_hdr *file_hdr = f->base;
	uint32_t nr_entries = ntohl(file_hdr->nr_entries);
	uint64_t start_of_data = (sizeof(struct idxf_hdr) + (sizeof(struct idxf_ent) * (uint64_t) nr_entries));
	if (f->len < start_of_data) {
		return 0;
	}
	struct idxf_ent dummy_ent = {htonl(idx_ent[1]), 0};
	struct idxf_ent *found_ent = bsearch(&file_hdr[1], sizeof(struct idxf_ent), nr_entries, compare_idxf_ent);
	if (!found_ent) return 0;
	uint64_t data_offset = start_of_data + (((uint64_t) ntohl(found_ent->data_offset)) << 2);
	int is_empty = 1;
	for (int i = 0; i < 128; i++) {
		uint64_t effective_offset = data_offset + i;
		if (effective_offset >= f->len) break;
		char c = ((char *)f->base)[effective_offset];
		if (c == 0) break;
		domain_result[i] = c;
		is_empty = 0;
	}
	if (is_empty) return 0;
fill_domain:;
	char ip_hex[32];
	int ip_hex_i = 31;
	for (int i = 0; i < 16; i++) {
		ip_hex[i*2] = "0123456789abcdef"[ip[i] >> 4];
		ip_hex[i*2+1] = "0123456789abcdef"[ip[i] & 0xf];
	}
	for (int i = 127; i >= 0; i--) {
		if (domain_result[i] == '#') {
			if (ip_hex_i < 0) domain_result[i] = '0';
			domain_result[i] = ip_hex[ip_hex_i];
			ip_hex_i--;
		}
	}
	return 1;
}
