##### crackmes.one: VaultBreaker #####

This is a classic password cracking challenge,
first thing that caught my eye was the CheckPassword function.
Quickly, I notice that the variable v7 is set to a byte array named kEncoded

i also noticed this decryption loop which takes every byte of the encoded password 
and xors it with 0x5a

####
    do
    {
      pass_char = kEncoded[v2];
      if ( !v10 || *(int *)v10 > 1 )
        QByteArray::reallocData(&v10, v12, 1);
      *((_BYTE *)s2 + v2++) = pass_char ^ 0x5A;
    }
    while ( v2 != 10 );
####

and the decoded password is then compared with the password we feed into the program

So i took every byte of the password and xored it again with 0x5a which reverses
the operation

####
hex_char = [0x15, 0x2a, 0x69, 0x34, 0x09, 0x69, 0x29, 0x3b, 0x37, 0x3f]
xor_key = 0x5a
password = ""

for b in hex_char:
    print(f"Byte: {hex(b)}, Key: {hex(xor_key)}, XOR Result: {hex(b ^ xor_key)} -> '{chr(b ^ xor_key)}'")
    password += chr(b ^ xor_key)

print("Final Result:", password)
####

####
Byte: 0x15, Key: 0x5a, XOR Result: 0x4f -> 'O'
Byte: 0x2a, Key: 0x5a, XOR Result: 0x70 -> 'p'
Byte: 0x69, Key: 0x5a, XOR Result: 0x33 -> '3'
Byte: 0x34, Key: 0x5a, XOR Result: 0x6e -> 'n'
Byte: 0x9, Key: 0x5a, XOR Result: 0x53 -> 'S'
Byte: 0x69, Key: 0x5a, XOR Result: 0x33 -> '3'
Byte: 0x29, Key: 0x5a, XOR Result: 0x73 -> 's'
Byte: 0x3b, Key: 0x5a, XOR Result: 0x61 -> 'a'
Byte: 0x37, Key: 0x5a, XOR Result: 0x6d -> 'm'
Byte: 0x3f, Key: 0x5a, XOR Result: 0x65 -> 'e'
Final Result: Op3nS3same
####

So i input the password 'Op3nS3same' and it's correct