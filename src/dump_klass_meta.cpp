// ============================================================================
// RR02/dump_klass_meta.cpp — Dump Il2CppClass using IL2CPP metadata structures
// 
// On IL2CPP v39, the Il2CppClass struct has fields at these offsets:
//   based on https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Il2Cpp/Il2Cpp.cs
//   and il2cpp source code
//
// Il2CppClass v39:
//   0x00: Il2CppImage* image
//   0x08: void* gc_desc
//   0x10: const char* name
//   0x18: const char* namespaze
//   0x20: Il2CppType byval_arg (16 bytes)
//   0x30: Il2CppType this_arg (16 bytes)
//   0x40: Il2CppClass* element_class
//   0x48: Il2CppClass* castClass
//   0x50: Il2CppClass* declaring_type
//   0x58: Il2CppClass* parent
//   0x60: Il2CppGenericClass* generic_class
//   0x68: ...
//   0x70: Il2CppClass* nested_classes
//   0x78: Il2CppClass* implementing_classes
//   0x80: Il2CppInteropData* interop_data
//   0x88: ...
//   0x90: ...
//   0x98: ...
//   0xA0: ...
//   0xA8: ...
//   0xB0: ...
//   0xB8: FieldInfo* fields  ← THIS is what we want
//   0xC0: MethodInfo** methods
//   ...
//   0xD8: uint16_t method_count
//   ...
//   0xE0: uint16_t property_count
//   0xE2: uint16_t field_count  ← and THIS
//   ...
//   0xF0: uint32_t size
//   ...
//
// Wait, these offsets are for IL2CPP v24.x. For v39, the struct layout
// is different. Let me just dump the FULL 0x300 bytes and search more
// carefully.
//
// Actually, let's look at the v39 Il2CppClass struct from the source:
//
// struct Il2CppClass {
//     const Il2CppImage* image;          // 0x00
//     void* gc_desc;                      // 0x08
//     const char* name;                   // 0x10
//     const char* namespaze;              // 0x18
//     Il2CppType byval_arg;              // 0x20 (16 bytes)
//     Il2CppType this_arg;               // 0x30 (16 bytes)
//     Il2CppClass* element_class;        // 0x40
//     Il2CppClass* castClass;             // 0x48
//     Il2CppClass* declaring_type;        // 0x50
//     Il2CppClass* parent;                // 0x58
//     Il2CppGenericClass* generic_class; // 0x60
//     ...
//     // On v39, fields might be at 0xB8 or different offset
//     // Let's look for the actual pattern
// }
//
// FieldInfo v39:
// struct FieldInfo {
//     const Il2CppType* type;     // 0x00 (8 bytes)
//     const char* name;           // 0x08 (8 bytes)  
//     Il2CppClass* parent;        // 0x10 (8 bytes)
//     int32_t offset;              // 0x18 (4 bytes)
//     uint32_t token;              // 0x1C (4 bytes)
// };
// = 32 bytes
//
// OR on v39:
// struct FieldInfo {
//     const char* name;           // 0x00 (8 bytes)
//     const Il2CppType* type;     // 0x08 (8 bytes)
//     int32_t offset;             // 0x10 (4 bytes)
//     uint32_t token;              // 0x14 (4 bytes)
//     Il2CppClass* parent;        // 0x18 (8 bytes)
// };
// = 32 bytes
//
// Let's try ALL these layouts and also scan the ENTIRE 0x300 bytes