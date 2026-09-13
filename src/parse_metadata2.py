#!/usr/bin/env python3
"""
RR02/parse_metadata2.py — Parse IL2CPP v39 global-metadata.dat correctly.
Based on the actual v39 header layout from Il2CppDumper source code.
"""
import struct, sys

META_PATH = "/Users/mac/Library/Application Support/Steam/steamapps/common/Rust/RustClient.app/Contents/Resources/Data/il2cpp_data/Metadata/global-metadata.dat"

with open(META_PATH, "rb") as f:
    data = f.read()

sanity = struct.unpack_from("<I", data, 0)[0]
version = struct.unpack_from("<i", data, 4)[0]
print(f"Sanity: 0x{sanity:08X}, Version: {version}")
assert sanity == 0xFAB11BAF

# IL2CPP v39 header layout (from Il2CppDapper/Il2Cpp/Metadata.cs)
# Each entry is (offset: int32, count: int32) = 8 bytes
# struct Il2CppGlobalMetadataHeader {
#   int32_t sanity;
#   int32_t version;
#   int32_t stringLiteralOffset;         // 0x08
#   int32_t stringLiteralCount;            // 0x0C
#   int32_t stringLiteralDataOffset;       // 0x10
#   int32_t stringLiteralDataCount;        // 0x14
#   int32_t stringOffset;                  // 0x18
#   int32_t stringSize;                    // 0x1C
#   int32_t eventsOffset;                  // 0x20
#   int32_t eventsSize;                    // 0x24
#   int32_t propertiesOffset;             // 0x28
#   int32_t propertiesSize;                // 0x2C
#   int32_t methodsOffset;                 // 0x30
#   int32_t methodsSize;                   // 0x34
#   int32_t parameterDefaultValuesOffset;  // 0x38
#   int32_t parameterDefaultValuesSize;    // 0x3C
#   int32_t fieldDefaultValuesOffset;      // 0x40
#   int32_t fieldDefaultValuesSize;        // 0x44
#   int32_t fieldAndParameterDefaultValueDataOffset; // 0x48
#   int32_t fieldAndParameterDefaultValueDataSize; // 0x4C
#   int32_t fieldMarshaledSizesOffset;     // 0x50
#   int32_t fieldMarshaledSizesSize;       // 0x54
#   int32_t parametersOffset;              // 0x58
#   int32_t parametersSize;                // 0x5C
#   int32_t fieldsOffset;                  // 0x60  ← Field definitions!
#   int32_t fieldsSize;                     // 0x64
#   int32_t genericParametersOffset;       // 0x68
#   int32_t genericParametersSize;        // 0x6C
#   int32_t genericParameterConstraintsOffset; // 0x70
#   int32_t genericParameterConstraintsSize;  // 0x74
#   int32_t genericContainerOffset;        // 0x78
#   int32_t genericContainerSize;         // 0x7C
#   int32_t nestedTypesOffset;             // 0x80
#   int32_t nestedTypesSize;              // 0x84
#   int32_t interfacesOffset;              // 0x88
#   int32_t interfacesSize;               // 0x8C
#   int32_t vtableMethodsOffset;           // 0x90
#   int32_t vtableMethodsSize;            // 0x94
#   int32_t interfaceOffsetsOffset;        // 0x98
#   int32_t interfaceOffsetsSize;         // 0x9C
#   int32_t typeDefsOffset;               // 0xA0  ← Type definitions!
#   int32_t typeDefsSize;                 // 0xA4
#   int32_t imagesOffset;                 // 0xA8
#   int32_t imagesSize;                  // 0xAC
#   int32_t assembliesOffset;             // 0xB0
#   int32_t assembliesSize;             // 0xB4
# }

def rd(off, count=1):
    return struct.unpack_from(f"<{count}i", data, off)

string_off, string_sz = rd(0x18, 2)
fields_off, fields_sz = rd(0x60, 2)
typedefs_off, typedefs_sz = rd(0xA0, 2)
images_off, images_sz = rd(0xA8, 2)

print(f"String table:      offset=0x{string_off:08X}, size={string_sz}")
print(f"Fields table:      offset=0x{fields_off:08X}, size={fields_sz}")
print(f"TypeDefs table:    offset=0xtypedefs_off:08X, size={typedefs_sz}")
print(f"typedefs_off={typedefs_off}")

# Il2CppFieldDefinition (v39):
#   nameIndex (int32)
#   typeIndex (int32)  
#   token (uint32)
# = 12 bytes
FIELD_SIZE = 12

# Il2CppTypeDefinition (v39):
#   nameIndex (int32)            0
#   namespaceIndex (int32)       4
#   byvalTypeIndex (int32)       8
#   declaringTypeIndex (int32?)  12
#   parentIndex (int32)           16
#   elementTypeIndex (int32)     20
#   genericContainerIndex (int32) 24
#   flags (int32)                 28
#   fieldStart (int32)            32
#   methodStart (int32)           36
#   eventStart (int32)            40
#   propertyStart (int32)         44
#   nestedTypesStart (int32)      48
#   interfacesStart (int32)       52
#   vtableStart (int32)            56
#   interfaceOffsetsStart (int32) 60
#   method_count (uint16)         64
#   property_count (uint16)       66
#   field_count (uint16)          68
#   event_count (uint16)           70
#   nested_type_count (uint16)    72
#   vtable_count (uint16)          74
#   interfaces_count (uint16)      76
#   interface_offsets_count (uint16) 78
#   bitfield (uint32)             80
#   token (uint32)                84
# Total = 88 bytes
TYPEDEF_SIZE = 88

# Try with different TypeDef sizes if 88 doesn't work
for ts in [88, 92, 96, 100, 104, 108, 112]:
    n_typedefs = typedefs_sz // ts
    if n_typedefs > 0 and typedefs_sz % ts == 0 or n_typedefs > 0:
        # Try to read first TypeDef name
        if typedefs_off + 0 < len(data):
            ni = struct.unpack_from("<i", data, typedefs_off)[0]
            if 0 <= ni < string_sz:
                name_str = data[string_off + ni: string_off + ni + 64].split(b'\x00')[0].decode('utf-8', errors='replace')
                print(f"  TypeDef size {ts}: {n_typedefs} typedefs, first='{name_str}'")

# Let's try 88 first
TYPEDEF_SIZE = 88
n_typedefs = typedefs_sz // TYPEDEF_SIZE
print(f"\nUsing TypeDef size={TYPEDEF_SIZE}, count={n_typedefs}")

def get_string(idx):
    if idx < 0 or idx >= string_sz: return ""
    s = data[string_off + idx: string_off + idx + 128]
    return s.split(b'\x00')[0].decode('utf-8', errors='replace')

def get_field_name(idx):
    off = fields_off + idx * FIELD_SIZE
    if off + 4 > len(data): return ""
    ni = struct.unpack_from("<i", data, off)[0]
    return get_string(ni)

# Search for BasePlayer TypeDef
print("\n=== Searching for BasePlayer TypeDef ===")
for i in range(n_typedefs):
    off = typedefs_off + i * TYPEDEF_SIZE
    if off + TYPEDEF_SIZE > len(data): break
    name_idx = struct.unpack_from("<i", data, off)[0]
    name = get_string(name_idx)
    if name == "BasePlayer":
        ns_idx = struct.unpack_from("<i", data, off + 4)[0]
        ns = get_string(ns_idx)
        parent_idx = struct.unpack_from("<i", data, off + 16)[0]
        field_start = struct.unpack_from("<i", data, off + 32)[0]
        field_count = struct.unpack_from("<H", data, off + 68)[0]
        print(f"\n=== FOUND! ===")
        print(f"  TypeDef index: {i}")
        print(f"  Name: {name}")
        print(f"  Namespace: {ns}")
        print(f"  Parent index: {parent_idx}")
        print(f"  Field start: {field_start}")
        print(f"  Field count: {field_count}")
        
        print(f"\n  === Fields ===")
        for fi in range(field_count):
            foff = fields_off + (field_start + fi) * FIELD_SIZE
            if foff + FIELD_SIZE > len(data): break
            f_name_idx = struct.unpack_from("<i", data, foff)[0]
            f_type_idx = struct.unpack_from("<i", data, foff + 4)[0]
            f_token = struct.unpack_from("<I", data, foff + 8)[0]
            f_name = get_string(f_name_idx)
            print(f"    [{fi}] name=\"{f_name}\" typeIndex={f_type_idx} token=0x{f_token:08X}")
        
        # Also dump parent TypeDef
        if parent_idx >= 0 and parent_idx < n_typedefs:
            poff = typedefs_off + parent_idx * TYPEDEF_SIZE
            p_name = get_string(struct.unpack_from("<i", data, poff)[0])
            p_field_start = struct.unpack_from("<i", data, poff + 32)[0]
            p_field_count = struct.unpack_from("<H", data, poff + 68)[0]
            print(f"\n  === Parent: {p_name} ===")
            print(f"  Field start: {p_field_start}, Field count: {p_field_count}")
            for fi in range(p_field_count):
                foff = fields_off + (p_field_start + fi) * FIELD_SIZE
                if foff + FIELD_SIZE > len(data): break
                f_name_idx = struct.unpack_from("<i", data, foff)[0]
                f_name = get_string(f_name_idx)
                print(f"    [{fi}] name=\"{f_name}\"")
        
        # Walk up parent chain
        print(f"\n  === Parent chain ===")
        cur_parent = parent_idx
        depth = 0
        while cur_parent >= 0 and cur_parent < n_typedefs and depth < 15:
            poff = typedefs_off + cur_parent * TYPEDEF_SIZE
            p_name = get_string(struct.unpack_from("<i", data, poff)[0])
            p_fs = struct.unpack_from("<i", data, poff + 32)[0]
            p_fc = struct.unpack_from("<H", data, poff + 68)[0]
            print(f"    {'  '*depth}{p_name} (fields: {p_fs}..{p_fs+p_fc})")
            for fi in range(p_fc):
                foff = fields_off + (p_fs + fi) * FIELD_SIZE
                if foff + FIELD_SIZE > len(data): break
                f_name_idx = struct.unpack_from("<i", data, foff)[0]
                f_name = get_string(f_name_idx)
                print(f"      {'  '*depth}+ \"{f_name}\"")
            cur_parent = struct.unpack_from("<i", data, poff + 16)[0]
            depth += 1
        break