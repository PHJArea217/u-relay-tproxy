import shlex, sys, ipaddress, struct
def gen_file(maps):
    path_map = {}
    path_data = b''
    data_entries = []
    for ip, path, the_type in maps:
        entry = ip.network_address.packed + bytes([ip.prefixlen, the_type])
        if the_type == 3:
            path = ipaddress.IPv6Network((path, ip.prefixlen)).network_address
        if path not in path_map:
            if the_type == 3:
                new_offset = len(path_data)
                new_data = path.packed
                new_length = len(new_data)
            else:
                new_offset = len(path_data)
                new_data = bytes(path, encoding="utf-8") + b'\0'
                new_length = len(new_data)
            path_data = path_data + new_data
            path_map[path] = (new_offset, new_length)
        else:
            new_offset, new_length = path_map[path]
        entry = entry + struct.pack(">HIII", new_length, new_offset, 0, 0)
        data_entries.append(entry)
    entries_bytes = b''.join(data_entries)
    total_length = 16 + len(path_data) + len(entries_bytes)
    total_length_padded = (total_length + 4095) >> 12
    padding = (total_length_padded << 12) - total_length
    header = struct.pack(">IHHII", 0xf200a01f, len(data_entries), total_length_padded, 0, 0)
    padding_bytes = b'\0' * padding
    return header + entries_bytes + path_data + padding_bytes

with open(sys.argv[1], 'r') as source_file:
    lines = []
    for line in source_file.readlines():
        line_split = shlex.split(line, comments=True)
        if len(line_split) >= 2:
            lines.append((ipaddress.IPv6Network(line_split[0]),line_split[1],int(line_split[2] if len(line_split) >= 3 else "2")))
    with open(sys.argv[2], 'wb') as dest_file:
        dest_file.write(gen_file(lines))
