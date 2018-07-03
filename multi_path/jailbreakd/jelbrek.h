
void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base);
BOOL unsandbox(pid_t pid);
void setcsflags(pid_t pid);
BOOL get_root(pid_t pid);
void platformize(pid_t pid);
void entitlePid(pid_t pid, const char *ent1, BOOL val1);
