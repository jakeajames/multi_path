#import <Foundation/Foundation.h>
#include <err.h>
#include "kern_utils.h"
#include "patchfinder64.h"
#include "offsetof.h"
#include "jelbrek.h"
#include <sys/mount.h>
#include "kexecute.h"


void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base) {
    init_kernel_utils(tfp0);
    init_kernel(kernel_base, NULL);
}

BOOL unsandbox(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred); //our credentials
    kwrite64(kread64(ucred + 0x78) + 8 + 8, 0x0); //get rid of sandbox by writing 0x0 to it
    
    return (kread64(kread64(ucred + 0x78) + 8 + 8) == 0) ? YES : NO;
}

void setcsflags(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint32_t csflags = kread32(proc + offsetof_p_csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + offsetof_p_csflags, csflags);
}

void platformize(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    NSLog(@"Platformizing process at address 0x%llx\n", proc);
    uint64_t task = kread64(proc + offsetof_task);
    uint32_t t_flags = kread32(task + offsetof_t_flags);
    t_flags |= 0x400;
    NSLog(@"Flicking on task @0x%llx t->flags to have TF_PLATFORM (0x%x)..\n", task, t_flags);
    kwrite32(task+offsetof_t_flags, t_flags);
    uint32_t csflags = kread32(proc + offsetof_p_csflags);
    kwrite32(proc + offsetof_p_csflags, csflags | 0x24004001u);
}

BOOL get_root(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred);
    //make everything 0 without setuid(0), pretty straightforward. 
    kwrite32(proc + offsetof_p_uid, 0);
    kwrite32(proc + offsetof_p_ruid, 0);
    kwrite32(proc + offsetof_p_gid, 0);
    kwrite32(proc + offsetof_p_rgid, 0);
    kwrite32(ucred + offsetof_ucred_cr_uid, 0);
    kwrite32(ucred + offsetof_ucred_cr_ruid, 0);
    kwrite32(ucred + offsetof_ucred_cr_svuid, 0);
    kwrite32(ucred + offsetof_ucred_cr_ngroups, 1);
    kwrite32(ucred + offsetof_ucred_cr_groups, 0);
    kwrite32(ucred + offsetof_ucred_cr_rgid, 0);
    kwrite32(ucred + offsetof_ucred_cr_svgid, 0);
    
    return (geteuid() == 0) ? YES : NO;
}
void entitlePid(pid_t pid, const char *ent1, _Bool val1) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc+0x100);
    uint64_t entitlements = kread64(kread64(ucred+0x78)+0x8);
    
    uint64_t current = OSDictionary_GetItem(entitlements, ent1);
    
    if (current == 0) {
        usleep(1000);
        NSLog(@"[*] Setting Entitlements...");
        NSLog(@"before: %s is 0x%llx", ent1, current);
        usleep(1000);
        OSDictionary_SetItem(entitlements, ent1, (val1) ? find_OSBoolean_True() : find_OSBoolean_False());
        usleep(1000);
        NSLog(@"after: %s is 0x%llx", ent1, OSDictionary_GetItem(entitlements, ent1));
    }
}


