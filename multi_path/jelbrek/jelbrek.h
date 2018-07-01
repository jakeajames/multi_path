#include "QiLin.h"

void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base);
kern_return_t trust_bin(const char *path);
BOOL unsandbox(pid_t pid);
void setcsflags(pid_t pid);
BOOL get_root(pid_t pid);
void remount1126(void);
void mountDevAtPathAsRW(const char* devpath, const char* path);
void remount1131(void);
void platformize(pid_t pid);
void entitlePid(pid_t pid, const char *ent1, _Bool val1);
int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);
int launchAsPlatform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);
void undoCredDonation(uint64_t selfcred);
uint64_t borrowCredsFromPid(pid_t donor);
uint64_t borrowCredsFromDonor(char *binary);

