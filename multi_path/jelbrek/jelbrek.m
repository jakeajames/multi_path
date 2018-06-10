#import <Foundation/Foundation.h>
#include <err.h>
#include "kern_utils.h"
#include "patchfinder64.h"
#include "libjb.h"
#include "offsetof.h"
#include "jelbrek.h"
#include <sys/mount.h>

//#include "inject_criticald.h"
//#include "unlocknvram.h"
//#include <IOKit/IOKitLib.h>


void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base) {
    init_kernel_utils(tfp0);
    init_kernel(kernel_base, NULL);
    initQiLin(tfp0, kernel_base); //Jonathan Levin: http://newosxbook.com/QiLin/
}

kern_return_t trust_bin(const char *path) {
    uint64_t trust_chain = find_trustcache();
    uint64_t amficache = find_amficache();
    
    printf("[*] trust_chain at 0x%llx\n", trust_chain);
    printf("[*] amficache at 0x%llx\n", amficache);
    
    struct trust_mem mem;
    mem.next = kread64(trust_chain);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    
    int rv = grab_hashes(path, kread, amficache, mem.next);
    
    size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
    uint64_t kernel_trust = kalloc(length);
    printf("[*] alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    mem.count = numhash;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
    kwrite64(trust_chain, kernel_trust);
    
    free(allhash);
    free(allkern);
    free(amfitab);
    
    if (rv == 0)
        printf("[*] Successfully trusted binaries? return value=%d numhash=%d\n", rv, numhash);
    else
        printf("[*] Unknown error while trusting binaries! return value=%d numhash=%d", rv, numhash);
    return rv;
}


BOOL unsandbox(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred);
    kwrite64(kread64(ucred + 0x78) + 8 + 8, 0x0);
    
    return (kread64(kread64(ucred + 0x78) + 8 + 8) == 0) ? YES : NO;
}

void empower(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint32_t csflags = kread32(proc + offsetof_p_csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + offsetof_p_csflags, csflags);
}

BOOL get_root(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred);
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


/*void remount(){
    uint64_t _rootvnode = find_rootvnode();
    uint64_t rootfs_vnode = kread64(_rootvnode);
    uint64_t v_mount = kread64(rootfs_vnode + offsetof_v_mount);
    uint32_t v_flag = kread32(v_mount + offsetof_mnt_flag);
    
    v_flag = v_flag & ~MNT_NOSUID;
    v_flag = v_flag & ~MNT_RDONLY;
    
    kwrite32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
    
    char *nmz = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
    printf("remounting: %d\n", rv);
    
    v_mount = kread64(rootfs_vnode + offsetof_v_mount);
    kwrite32(v_mount + offsetof_mnt_flag, v_flag);
    
    int fd = open("/RWTEST", O_RDONLY);
    if (fd == -1) {
        fd = creat("/RWTEST", 0777);
    } else {
        printf("File already exists!\n");
    }
    close(fd);
    printf("Did we mount / as read+write? %s\n", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "yes" : "no");
}*/
