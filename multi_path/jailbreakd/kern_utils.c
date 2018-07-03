//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "kern_utils.h"
#include "patchfinder64.h"
#include "offsetof.h"
#include "offsets.h"
#include "kexecute.h"
#include "osobject.h"


/****** Kernel utility stuff ******/

mach_port_t tfpzero;

void init_kernel_utils(mach_port_t tfp0) {
    tfpzero = tfp0;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

void kfree(mach_vm_address_t address, vm_size_t size) {
    mach_vm_deallocate(tfpzero, address, size);
}

CACHED_FIND(uint64_t, our_task_addr) {
    uint64_t our_proc = proc_for_pid(getpid());
    
    if (our_proc == 0) {
        fprintf(stderr,"failed to find our_task_addr!\n");
        exit(EXIT_FAILURE);
    }
    
    uint64_t addr = kread64(our_proc + offsetof_task);
    fprintf(stderr,"our_task_addr: 0x%llx\n", addr);
    return addr;
}

uint64_t find_port_address(mach_port_name_t port) {
    uint64_t task_addr = our_task_addr();
    
    uint64_t itk_space = kread64(task_addr + offsetof_itk_space);
    
    uint64_t is_table = kread64(itk_space + offsetof_ipc_space_is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = kread64(is_table + (port_index * sizeof_ipc_entry_t));
    return port_addr;
}


size_t kread(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[*] error on kread(0x%016llx) AAA 0x%llx\n", (offset + where), where);
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread(where, &out, sizeof(uint64_t));
    return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (rv) {
            printf("[*] error on kwrite(0x%016llx) AAAN 0x%llx\n", (offset + where), where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

void kwrite32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t));
}


void kwrite64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite(where, &_what, sizeof(uint64_t));
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void kmemcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kwrite(dest, (void*) src, length);
    } else {
        // copy from kernel
        kread(src, (void*)dest, length);
    }
}

uint64_t proc_for_pid(pid_t pid) {
    uint64_t proc = kread64(find_allproc()), pd;
    while (proc) { //iterate over all processes till we find the one we're looking for
        pd = kread32(proc + offsetof_p_pid);
        if (pd == pid) return proc;
        proc = kread64(proc);
    }
    
    return 0;
}
uint64_t proc_for_name(char *nm) {
    uint64_t proc = kread64(find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + 0x268, name, 20); //read 20 bytes off the process's name and compare
        if (strstr(name, nm)) return proc;
        proc = kread64(proc);
    }
    return 0;
}


unsigned int pid_for_name(char *nm) {
    uint64_t proc = kread64(find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + 0x268, name, 20);
        if (strstr(name, nm)) return kread32(proc + offsetof_p_pid);
        proc = kread64(proc);
    }
    return 0;
}

uint64_t find_kernproc() {
    //since each process points to the next one and QiLin needs a pointer to kernproc find what's before it by doing kread64 twice I guess?
    uint64_t proc = kread64(find_allproc()), pd;
    while (proc) {
        pd = kread32(kread64(proc) + offsetof_p_pid);
        if (pd == 0) return proc;
        proc = kread64(proc);
    }
    
    return 0;
}

typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    
    if (zm_hdr.start == 0) {
        // xxx rk64(0) ?!
        uint64_t zone_map = kread64(find_zone_map_ref());
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        //printf("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            printf("kread of zone_map failed!\n");
            exit(1);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            printf("zone_map is too big, sorry.\n");
            exit(1);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

int remove_memory_limit(void) {
    // daemons run under launchd have a very stingy memory limit by default, we need
    // quite a bit more for patchfinder so disable it here
    // (note that we need the com.apple.private.memorystatus entitlement to do so)
    pid_t my_pid = getpid();
    return memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, my_pid, 0, NULL, 0);
}
