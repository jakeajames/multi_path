# rootless jailbreakd

A small jailbreakd offering some more functionality to the jailbreak. Uses CPDisctributedMessageCenter. To compile you need theos (why? cus why not? and I like theos. If you're smart enough you can still compile it manually very easily so yeah)

# Setup

- Grab AppSupport headers and add them into your include path (https://github.com/theos/headers/tree/05405174749d912f7726121fcb5f27de73af0f08/AppSupport)
- Include "AppSupport/CPDistributedMessagingCenter.h" on your main.m file
- Link with https://github.com/jakeajames/rootme-tutorial/blob/master/AppSupport.tbd
- The general syntax follows as this:
```
CPDistributedMessagingCenter *messageCenter = [CPDistributedMessagingCenter centerNamed:@"com.jakeashacks.rootme"];
[messageCenter sendMessageAndReceiveReplyName:@"MESSAGE_NAME" userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"%d", getpid()] forKey:@"pid"]];
```
# Compiling
    ./make.sh
# Commands

At the moment these commands are available

- "rootme": does setuid(0) and setgid(0) for you
- "unsandbox": gets rid of most of the sandbox (This will not be any useful right now since to call jailbreakd you have to be unsandboxed already)
- "platformize": marks your binary as platform by setting TF_PLATFORM and CS_PLATFORM_BINARY
- "setcsflags": Sets some flags such as CS_PLATFORM_BINARY, CS_GET_TASK_ALLOW, CS_DEBUGGED etc
- "entitle": Set entitlement to true or false. Example:
```
CPDistributedMessagingCenter *messageCenter = [CPDistributedMessagingCenter centerNamed:@"com.jakeashacks.rootme"];
NSMutableDictionary *dict = [NSMutableDictionary dictionary];
[dict setValue:@"com.apple.private.skip-library.validation" forKey:@"ent"]; //entitlement name
[dict setValue:@"true" forKey:@"value"]; //true or false
[dict setValue:[NSString stringWithFormat:@"%d", getpid()] forKey:@"pid"];
[messageCenter sendMessageAndReceiveReplyName:@"entitle" userInfo:dict];
```

# Do binaries need suid permissions or root ownership?

No. I didn't bother with that because a) There isn't a package manager so all binaries are controlled by you, b) there's no root remount thus nothing can cause a big mess, c) you need to be unsandboxed to make a call to jailbreakd (all binaries you run via SSH satisfy this requirement) and that's enough for me. Is it coming? Probably yes

# Coming soon

- I guess a nice response from jailbreakd telling us what happened in the other world
- (?) check for suid permissions and ownership
