#import <Foundation/Foundation.h>
#include <AppSupport/CPDistributedMessagingCenter.h>
#include <spawn.h>

int main(int argc, const char* argv[], const char* envp[]) {
    
    CPDistributedMessagingCenter *messageCenter = [CPDistributedMessagingCenter centerNamed:@"com.jakeashacks.jbclient"];
    
    pid_t pd;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    NSString *reallaunchctl = [NSString stringWithFormat:@"%@/launchctl_", [[NSBundle mainBundle] bundlePath]];
    
    int rv = posix_spawn(&pd, [reallaunchctl UTF8String], NULL, &attr, argv, envp);
    
    [messageCenter sendMessageAndReceiveReplyName:@"platformize" userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"%d", pd] forKey:@"pid"]];

    kill(pd, SIGCONT); //continue
    
    int a;
    waitpid(pd, &a, 0);
    
    return rv;
}
