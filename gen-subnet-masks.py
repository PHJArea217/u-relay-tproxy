#!/usr/bin/python3
print('#include <stdint.h>\n__attribute__((visibility("hidden")))\nconst uint8_t subnet_mask_data[129][16] = {')
arr = [0 for x in range(16)]
n = 0
while True:
    print('\t{' + ', '.join(str(i) for i in arr) + '},')
    arr[n] = 128 | (arr[n] >> 1)
    if arr[n] == 255:
        n = n + 1
    if n >= 16:
        break
print('\t{' + ', '.join("255" for i in range(16)) + '}')
print('};')
