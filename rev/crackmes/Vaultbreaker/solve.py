hex_char = [0x15, 0x2a, 0x69, 0x34, 0x09, 0x69, 0x29, 0x3b, 0x37, 0x3f]
xor_key = 0x5a
password = ""

for b in hex_char:
    print(f"Byte: {hex(b)}, Key: {hex(xor_key)}, XOR Result: {hex(b ^ xor_key)} -> '{chr(b ^ xor_key)}'")
    password += chr(b ^ xor_key)

print("Final Result:", password)

