#!/usr/bin/env python3
"""
RR02/parse_metadata.py — Parse global-metadata.dat v39 to find BasePlayer field offsets.
No injection, no process memory access — pure file parsing.
"""
import struct, sys, os

META_PATH = "/Users/mac/Library/Application Support/Steam/steamapps/common/Rust/RustClient.app/Contents/Resources/Data/il2cpp_data/Metadata/global-metadata.dat"

with open(META_PATH, "rb") as f:
    data = f.read()

print(f"Metadata size: {len(data)} bytes")

# Parse header (v39)
# struct Il2CppGlobalMetadataHeader:
#   0x00: int32 sanity (0xFAB11BAF)
#   0x04: int32 version
#   0x08: int32 stringLiteralOffset
#   0x0C: int32 stringLiteralCount
#   0x10: int32 stringLiteralDataOffset
#   0x14: int32 stringLiteralDataCount
#   ... many more offsets
#   We need: typeDefsOffset, typeDefsCount, fieldsOffset, fieldsCount
#            stringsOffset, stringsCount

off = 0
sanity = struct.unpack_from("<I", data, off)[0]; off += 4
version = struct.unpack_from("<i", data, off)[0]; off += 4
print(f"Sanity: 0x{sanity:08X}")
print(f"Version: {version}")

if sanity != 0xFAB11BAF:
    print("ERROR: Bad sanity"); sys.exit(1)

# For v39, the header has many fields. Let's read them all as int32 pairs (offset, count)
# We need to find: string, typeDef, field entries
# Each header entry is (offset: int32, count: int32) = 8 bytes

# Let's read all int32 values from the header to find patterns
# The header for v39 is quite large. Let's scan through it.

header_fields = []
for i in range(0, 2000, 4):
    if i + 4 > len(data): break
    val = struct.unpack_from("<i", data, i)[0]
    header_fields.append((i, val))

# Find key sections by looking for known patterns
# strings: large offset, large count
# typeDefs: offset, count * 108 (each TypeDef is 108 bytes on v39)
# fields: offset, count * 12 (each FieldInfo in metadata is typeIndex + nameIndex + offset + token = 8+8+4+4=24? or less)

# Actually for v39 metadata, the structures are:
# Il2CppTypeDefinition:
#   nameIndex (int32) - index into string table
#   namespaceIndex (int32)
#   byvalTypeIndex (int32)
#   ...
#   fieldStart (int32) - start index into field table
#   methodStart (int32)
#   ...
#   fieldCount (int16) - relative count
#   methodCount (int16)
#   ...

# Let's just search the entire metadata for the string "BasePlayer"
# and find its TypeDef

# First, find the strings section
# The strings section contains null-terminated strings
# We can find it by searching for known strings like "BasePlayer"

# Search for "BasePlayer" in the raw data
target = b"BasePlayer\x00"
positions = []
pos = 0
while True:
    pos = data.find(target, pos)
    if pos == -1: break
    positions.append(pos)
    pos += 1

print(f"\nFound 'BasePlayer' at {len(positions)} positions:")
for p in positions:
    # Read context around it
    start = max(0, p - 16)
    context = data[start:p+len(target)+16]
    print(f"  offset 0x{p:08X}: ...{context.hex()}...")

# Now we need to find the string table offset to calculate string indices
# The string table is a contiguous block of null-terminated strings
# If "BasePlayer" is at offset X in the file, and the string table starts at offset Y,
# then the string index = X - Y

# Let's find the string table by looking at the first few hundred bytes of the header
# The header structure for v39:
# 0x00: sanity (4)
# 0x04: version (4) = 39
# 0x08: stringLiteralOffset (4)
# 0x0C: stringLiteralCount (4) = number of string literals
# 0x10: stringLiteralDataOffset (4)
# 0x14: stringLiteralDataCount (4)
# 0x18: stringOffset (4)  ← string table offset!
# 0x1C: stringCount (4)  ← string table size!
# 0x20: eventsOffset (4)
# ...

string_offset = struct.unpack_from("<i", data, 0x18)[0]
string_count = struct.unpack_from("<i", data, 0x1C)[0]
print(f"\nString table: offset=0x{string_offset:08X}, count={string_count}")

# Verify: check if "BasePlayer" is within the string table
for p in positions:
    if p >= string_offset and p < string_offset + string_count:
        string_index = p - string_offset
        print(f"  → String index for 'BasePlayer' at file offset 0x{p:08X} = {string_index}")

# Now find TypeDefs
# The header has typeDefsOffset and typeDefsCount
# For v39, let's scan the header to find it
# Each TypeDef entry on v39 is typically 108 bytes
# struct Il2CppTypeDefinition (v39):
#   nameIndex (int32)
#   namespaceIndex (int32)
#   byvalTypeIndex (int32)
#   declaringTypeIndex (int32?) 
#   parentIndex (int32)
#   elementTypeIndex (int32)
#   genericContainerIndex (int32)
#   flags (int32)
#   fieldStart (int32)
#   methodStart (int32)
#   eventStart (int32)
#   propertyStart (int32)
#   nestedTypesStart (int32)
#   interfacesStart (int32)
#   vtableStart (int32)
#   interfaceOffsetsStart (int32)
#   method_count (uint16)
#   property_count (uint16)
#   field_count (uint16)  
#   event_count (uint16)
#   nested_type_count (uint16)
#   vtable_count (uint16)
#   interfaces_count (uint16)
#   interface_offsets_count (uint16)
#   bitfield (uint32)
#   token (uint32)

# Let's try different header offsets for typeDefs
# We'll scan the header looking for (offset, count) pairs where:
#   count * 108 stays within the file
#   offset is reasonable

print("\n=== Searching for TypeDefs section ===")
for hoff in range(0x20, 0x800, 8):  # skip first few known fields
    if hoff + 8 > len(data): break
    td_off = struct.unpack_from("<i", data, hoff)[0]
    td_cnt = struct.unpack_from("<i", data, hoff + 4)[0]
    if td_off < 0 or td_cnt < 0: continue
    if td_off == 0 or td_cnt == 0: continue
    if td_off + td_cnt * 108 > len(data): continue  
    if td_off > len(data): continue
    # Check if this looks like a TypeDef table
    # First entry should have a valid nameIndex (points into string table)
    first_name_idx = struct.unpack_from("<i", data, td_off)[0]
    if 0 <= first_name_idx < string_count:
        name_str = data[string_offset + first_name_idx:string_offset + first_name_idx + 64]
        name_str = name_str.split(b'\x00')[0].decode('utf-8', errors='replace')
        print(f"  Header offset 0x{hoff:04X}: tdOff=0x{td_off:08X}, tdCount={td_cnt}, first='{name_str}'")

# Similarly for fields
print("\n=== Searching for Fields section ===")
# Each field entry in metadata is typically 24 bytes on v39:
# struct Il2CppFieldDefinition:
#   nameIndex (int32) - index into string table
#   typeIndex (int32) - index into type table
#   token (uint32)
# = 12 bytes? Or with offset:
# Actually in metadata, field definitions are:
#   nameIndex (int32) + typeIndex (int32) + token (uint32) = 12 bytes
# But Il2CppFieldOffset is separate:
#   offset (int32) + typeIndex (int32) = 8 bytes per entry

# Let's search for field table and field offset table separately
for hoff in range(0x20, 0x800, 8):
    if hoff + 8 > len(data): break
    f_off = struct.unpack_from("<i", data, hoff)[0]
    f_cnt = struct.unpack_from("<i", data, hoff + 4)[0]
    if f_off < 0 or f_cnt < 0: continue
    if f_off == 0 or f_cnt == 0: continue
    if f_off + f_cnt * 12 > len(data): continue
    if f_off > len(data): continue
    # Check first entry: nameIndex should be valid
    first_ni = struct.unpack_from("<i", data, f_off)[0]
    if 0 <= first_ni < string_count:
        name_str = data[string_offset + first_ni:string_offset + first_ni + 64]
        name_str = name_str.split(b'\x00')[0].decode('utf-8', errors='replace')
        if len(name_str) > 0 and len(name_str) < 100:
            print(f"  Header 0x{hoff:04X}: fOff=0x{f_off:08X}, fCnt={f_cnt}, first='{name_str}'")