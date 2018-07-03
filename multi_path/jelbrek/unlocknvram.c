// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object
// async_wake satisfies those requirements
// however, I wasn't able to actually set or get ANY nvram variable
// not even userread/userwrite
// Guess sandboxing won't let to access nvram

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include "kern_utils.h"
#include "offsetof.h"
#include "../offsets.h"

// convertPropToObject calls getOFVariableType
// open convertPropToObject, look for first vtable call -- that'd be getOFVariableType
// find xrefs, figure out vtable start from that
// following are offsets of entries in vtable

// it always returns false
const uint64_t searchNVRAMProperty = 0x590;
// 0 corresponds to root only
const uint64_t getOFVariablePerm = 0x558;

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);


// get kernel address of IODTNVRAM object
uint64_t get_iodtnvram_obj(void) {
    // get user serv
    io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    
    // leak user serv
    uint64_t nvram_up = find_port_address(IODTNVRAMSrv);
    // get kern obj -- IODTNVRAM*
    uint64_t IODTNVRAMObj = kread64(nvram_up + offsetof_ip_kobject);
    
    return IODTNVRAMObj;
}

void unlocknvram(void) {
    const uint64_t searchNVRAMProperty = 0x590;
    // 0 corresponds to root only
    const uint64_t getOFVariablePerm = 0x558;
    // get user serv
    io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    
    // leak user serv
    // it should use via_kmem_read method by now, so second param doesn't matter
    uint64_t nvram_up = find_port_address(IODTNVRAMSrv);
    // get kern obj -- IODTNVRAM*
    uint64_t IODTNVRAMObj = kread64(nvram_up + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t vtable_start = kread64(IODTNVRAMObj);
    uint64_t vtable_end = vtable_start;
    // Is vtable really guaranteed to end with 0 or was it just a coincidence?..
    // should we just use some max value instead?
    while (kread64(vtable_end) != 0) vtable_end += sizeof(uint64_t);
    
    uint32_t vtable_len = (uint32_t) (vtable_end - vtable_start);
    
    // copy vtable to userspace
    uint64_t *buf = calloc(1, vtable_len);
    kread(vtable_start, buf, vtable_len);
    
    // alter it
    buf[getOFVariablePerm/sizeof(uint64_t)] = buf[searchNVRAMProperty/sizeof(uint64_t)];
    
    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = kmem_alloc_wired(vtable_len);
    kwrite(fake_vtable, buf, vtable_len);
    
    // replace vtable on IODTNVRAM object
    kwrite64(IODTNVRAMObj, fake_vtable);
    
    free(buf);
}
