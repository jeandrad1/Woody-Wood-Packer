#!/bin/bash

# This script automates the process of converting the compiled stub (stub.bin) 
# into a C header file (stub_bytes.h) so the packer can hold the raw machine code.
# It calculates crucial offsets relative to the end of the stub where the packer 
# will dynamically inject data (encryption key, section address, size, entry point) 
# before inserting the stub into the target ELF file. 
# It also updates the STUB_SIZE macro in the main project header.

STUB_SIZE=$(wc -c < obj/stub.bin)
KEY_OFF=$((STUB_SIZE - 40))
ADDR_OFF=$((STUB_SIZE - 24))
SIZE_OFF=$((STUB_SIZE - 16))
ENTRY_OFF=$((STUB_SIZE - 8))

cat > src/stub_bytes.h <<STUB
#ifndef STUB_BYTES_H
# define STUB_BYTES_H

# define STUB_KEY_OFFSET        $KEY_OFF
# define STUB_SEG_ADDR_OFFSET   $ADDR_OFF
# define STUB_SEG_SIZE_OFFSET   $SIZE_OFF
# define STUB_ENTRY_OFFSET      $ENTRY_OFF

$(xxd -i obj/stub.bin | sed '1s/.*/static unsigned char stub_bin[] = {/' | grep -v 'unsigned int')

#endif
STUB

sed -i -E "s/#\s*define\s+STUB_SIZE\s+[0-9]+/#define STUB_SIZE $STUB_SIZE/" include/woody-woodpacker.h
