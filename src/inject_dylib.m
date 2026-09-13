// ============================================================================
// RR02/radar_inject.m — DYLIB injectée dans Rust qui utilise les fonctions
// il2cpp exportées pour retrouver BasePlayer et ses champs.
//
// Inject via DYLD_INSERT_LIBRARIES:
//   sudo DYLD_INSERT_LIBRARIES=/Users/mac/Desktop/RR02/src/radar_inject.dylib \
//     /path/to/RustClient
//
// Mais comme Rust est déjà lancé, on utilise ptrace ou thread injection.
// Plus simple: on écrit une dylib qui, au chargement, scanne la mémoire
// via les API il2cpp exportées et dump les offsets dans un fichier.
//
// La dylib sera chargée en utilisant lldbm ou un injector.
// ============================================================================

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// IL2CPP function pointers
typedef void* (*il2cpp_domain_get_t)(void);
typedef const char* (*il2cpp_image_get_name_t)(void* image);
typedef int (*il2cpp_image_get_class_count_t)(void* image);
typedef void* (*il2cpp_image_get_class_t)(void* image, int index);
typedef const char* (*il2cpp_class_get_name_t)(void* klass);
typedef const char* (*il2cpp_class_get_namespace_t)(void* klass);
typedef void* (*il2cpp_class_get_parent_t)(void* klass);
typedef int (*il2cpp_class_get_field_count_t)(void* klass);
typedef void* (*il2cpp_class_get_fields_t)(void* klass, void** iter);
typedef const char* (*il2cpp_field_get_name_t)(void* field);
typedef int (*il2cpp_field_get_offset_t)(void* field);

static void dump_class(void* klass, FILE* f, int depth);
static void dump_class_hierarchy(void* klass, FILE* f, int depth);

__attribute__((constructor))
static void init() {
    // Wait a bit for IL2CPP to initialize
    sleep(5);
    
    FILE* f = fopen("/Users/mac/Desktop/RR02/il2cpp_dump.txt", "w");
    if (!f) f = stderr;
    
    fprintf(f, "=== RR02 IL2CPP Runtime Dump ===\n");
    
    // Get IL2CPP functions
    void* lib = dlopen(NULL, RTLD_NOW);
    if (!lib) { fprintf(f, "dlopen failed: %s\n", dlerror()); fclose(f); return; }
    
    auto il2cpp_domain_get = (il2cpp_domain_get_t)dlsym(lib, "il2cpp_domain_get");
    auto il2cpp_domain_get_assemblies = (void* (*)(void*, size_t*))dlsym(lib, "il2cpp_domain_get_assemblies");
    auto il2cpp_assembly_get_image = (void* (*)(void*))dlsym(lib, "il2cpp_assembly_get_image");
    auto il2cpp_image_get_name = (il2cpp_image_get_name_t)dlsym(lib, "il2cpp_image_get_name");
    auto il2cpp_image_get_class_count = (il2cpp_image_get_class_count_t)dlsym(lib, "il2cpp_image_get_class_count");
    auto il2cpp_image_get_class = (il2cpp_image_get_class_t)dlsym(lib, "il2cpp_image_get_class");
    auto il2cpp_class_get_name = (il2cpp_class_get_name_t)dlsym(lib, "il2cpp_class_get_name");
    auto il2cpp_class_get_namespace = (il2cpp_class_get_namespace_t)dlsym(lib, "il2cpp_class_get_namespace");
    auto il2cpp_class_get_parent = (il2cpp_class_get_parent_t)dlsym(lib, "il2cpp_class_get_parent");
    auto il2cpp_class_get_fields = (il2cpp_class_get_fields_t)dlsym(lib, "il2cpp_class_get_fields");
    auto il2cpp_field_get_name = (il2cpp_field_get_name_t)dlsym(lib, "il2cpp_field_get_name");
    auto il2cpp_field_get_offset = (il2cpp_field_get_offset_t)dlsym(lib, "il2cpp_field_get_offset");
    auto il2cpp_class_instance_size = (int (*)(void*))dlsym(lib, "il2cpp_class_instance_size");
    
    if (!il2cpp_domain_get) { fprintf(f, "il2cpp_domain_get not found\n"); fclose(f); return; }
    fprintf(f, "[+] IL2CPP functions loaded\n");
    
    void* domain = il2cpp_domain_get();
    if (!domain) { fprintf(f, "domain is null\n"); fclose(f); return; }
    fprintf(f, "[+] Domain: %p\n", domain);
    
    size_t assembly_count = 0;
    void** assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    fprintf(f, "[+] %zu assemblies\n", assembly_count);
    
    // Find all classes named "BasePlayer" or "PlayerModel" or "BaseCombatEntity"
    for (size_t ai = 0; ai < assembly_count; ai++) {
        void* image = il2cpp_assembly_get_image(assemblies[ai]);
        const char* iname = il2cpp_image_get_name(image);
        int class_count = il2cpp_image_get_class_count(image);
        
        for (int ci = 0; ci < class_count; ci++) {
            void* klass = il2cpp_image_get_class(image, ci);
            const char* name = il2cpp_class_get_name(klass);
            const char* ns = il2cpp_class_get_namespace(klass);
            
            if (name && (strcmp(name, "BasePlayer") == 0 ||
                         strcmp(name, "BaseCombatEntity") == 0 ||
                         strcmp(name, "BaseEntity") == 0 ||
                         strcmp(name, "BaseNetworkable") == 0 ||
                         strcmp(name, "PlayerModel") == 0)) {
                fprintf(f, "\n=== %s::%s @ %p ===\n", ns ? ns : "", name, klass);
                if (il2cpp_class_instance_size)
                    fprintf(f, "  instance_size: %d\n", il2cpp_class_instance_size(klass));
                dump_class_hierarchy(klass, f, 0);
            }
        }
    }
    
    fprintf(f, "\n=== DONE ===\n");
    fclose(f);
}

void dump_class(void* klass, FILE* f, int depth) {
    auto il2cpp_class_get_name = (il2cpp_class_get_name_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_name");
    auto il2cpp_class_get_fields = (il2cpp_class_get_fields_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_fields");
    auto il2cpp_field_get_name = (il2cpp_field_get_name_t)dlsym(RTLD_DEFAULT, "il2cpp_field_get_name");
    auto il2cpp_field_get_offset = (il2cpp_field_get_offset_t)dlsym(RTLD_DEFAULT, "il2cpp_field_get_offset");
    
    const char* name = il2cpp_class_get_name ? il2cpp_class_get_name(klass) : "?";
    fprintf(f, "%*sClass %s @ %p\n", depth*2, "", name, klass);
    
    if (il2cpp_class_get_fields && il2cpp_field_get_name && il2cpp_field_get_offset) {
        void* iter = NULL;
        void* field;
        while ((field = il2cpp_class_get_fields(klass, &iter)) != NULL) {
            const char* fname = il2cpp_field_get_name(field);
            int foff = il2cpp_field_get_offset(field);
            fprintf(f, "%*s  +0x%04x  %s\n", depth*2, "", foff, fname ? fname : "?");
        }
    }
}

void dump_class_hierarchy(void* klass, FILE* f, int depth) {
    auto il2cpp_class_get_name = (il2cpp_class_get_name_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_name");
    auto il2cpp_class_get_parent = (il2cpp_class_get_parent_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_parent");
    auto il2cpp_class_get_fields = (il2cpp_class_get_fields_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_fields");
    auto il2cpp_field_get_name = (il2cpp_field_get_name_t)dlsym(RTLD_DEFAULT, "il2cpp_field_get_name");
    auto il2cpp_field_get_offset = (il2cpp_field_get_offset_t)dlsym(RTLD_DEFAULT, "il2cpp_field_get_offset");
    
    dump_class(klass, f, depth);
    
    if (il2cpp_class_get_parent) {
        void* parent = il2cpp_class_get_parent(klass);
        if (parent && depth < 10) {
            dump_class_hierarchy(parent, f, depth + 1);
        }
    }
}