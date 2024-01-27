import sys, json, struct, os
input_json = json.load(open(sys.argv[1], 'r'))
out_fn = sys.argv[2]
with open(out_fn + '.tmp', 'wb') as out_file:
	entries = []
	domain_buffers = []
	domain_position = 0
	for d, i in input_json['relay_map']:
		domain_buf = bytes(d, encoding='utf-8')
		domain_buffers.append(domain_buf)
		extra = b'\0' * (4-(len(domain_buf) & 3))
		domain_buffers.append(extra)
		entries.append((i, struct.pack('>II', i, domain_position >> 2)))
		domain_position = domain_position + len(extra) + len(domain_buf)
		assert (domain_position & 3) == 0
	out_file.write(struct.pack('>II', 0xf200a01e, len(entries)))
	entries.sort(key=lambda x: x[0])
	for e in entries:
		out_file.write(e[1])
	for b in domain_buffers:
		out_file.write(b)
os.rename(out_fn + '.tmp', out_fn)
