#include "type4.h"
#include <string.h>
extern char subnet_mask_data[129][16];
static int apply_subnet_mask(uint64_t r[2], const uint64_t s[2], unsigned int mask) {
	if (mask >= 129) return 1;
	uint64_t *m = (uint64_t *) &subnet_mask_data[mask][0];
	r[0] = (r[0] & ~m[0]) | (s[0] & m[0]);
	r[1] = (r[1] & ~m[1]) | (s[1] & m[1]);
	return 0;
}
int apply_t5_data_header(const struct sockaddr_in6 *in6, const struct type5_data *data, struct pp2_header *header) {
	struct type5_data dummy = {.flags = TYPE5_FLAG_KEEP_OUTER_PORT, .version = 1};
	if (!data) data = &dummy;
	if (data->version != 1) return 2;
	memcpy(header->data.ipv6.local, &in6->sin6_addr, 16);
	if (apply_subnet_mask((uint64_t *) &header->data.ipv6.local[0], (const uint64_t *) &data->outer_ip[0], data->outer_ip_mask)) {
		return 1;
	}
	if (data->flags & TYPE5_FLAG_KEEP_OUTER_PORT) {
		header->data.ipv6.local_port = in6->sin6_port;
	} else {
		header->data.ipv6.local_port = data->outer_port;
	}
	if (data->flags & TYPE5_FLAG_SEND_INNER) {
		header->data.ipv6.inner.header_version = htonl(0xe0001b01);
		memcpy(header->data.ipv6.inner.inner_ip, &in6->sin6_addr, 16);
		if (apply_subnet_mask((uint64_t *) &header->data.ipv6.inner.inner_ip[0], (const uint64_t *) &data->inner_ip[0], data->inner_ip_mask)) {
			return 1;
		}
		if (data->flags & TYPE5_FLAG_KEEP_INNER_PORT) {
			header->data.ipv6.inner.inner_port = in6->sin6_port;
		} else {
			header->data.ipv6.inner.inner_port = data->outer_port;
		}
	}
	return 0;
}
