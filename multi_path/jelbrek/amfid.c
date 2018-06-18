#include <stdlib.h>
#include "kexecute.h"
#include "kmem.h"
#include "kern_utils.h"
#include "patchfinder64.h"
#include <pthread/pthread.h>
#include "inject_criticald.h"


/*int proc_pidinfo(int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t * retval);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern int setExceptionHandlerForTask(task_t a1, void *a2);
extern int exceptionHandler(mach_port_name_t a1);

int patchAmfid() {
    pid_t pid = pid_for_name("amfid");
    task_t amfid_task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &amfid_task);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task for pid %u!", pid);
        return -1;
    }
    setExceptionHandlerForTask(amfid_task, (void*)exceptionHandler);
    
    return 0;
}
*/

/////////////////////////////////////////////

#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;


#include <stdlib.h>
#include <memory.h>


/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
    WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
    WORD i;
    
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
    WORD i;
    
    i = ctx->datalen;
    
    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    
    // Append to the padding the total message's length in bits and transform.
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    
    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}
/////////////////////////////////////////////////////////
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);

uint64_t amfid_base;
pthread_t exception_thread;
mach_port_t amfid_exception_port = MACH_PORT_NULL;

uint64_t old_amfid_MISVSACI;
uint64_t kill_thread_flag;

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exception_raise_reply;
#pragma pack()


void* rmem(mach_port_t tp, uint64_t addr, uint64_t len) {
    kern_return_t err;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    err = mach_vm_read(tp,
                       addr,
                       len,
                       &buf,
                       &num);
    if (err != KERN_SUCCESS) {
        printf("read failed\n");
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}

// copy pasta from mach_portal
void* rkmem(uint64_t addr, uint64_t len) {
    return rmem(tfp0, addr, len);
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w8(mach_port_t tp, uint64_t addr, uint8_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  1);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w32(mach_port_t tp, uint64_t addr, uint32_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  4);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w64(mach_port_t tp, uint64_t addr, uint64_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  8);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint16_t bswap16(uint16_t a)
{
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    return a;
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint32_t bswap32(uint32_t a)
{
    a = ((a & 0x000000FF) << 24) |
    ((a & 0x0000FF00) <<  8) |
    ((a & 0x00FF0000) >>  8) |
    ((a & 0xFF000000) >> 24);
    return a;
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint64_t bswap64(uint64_t a)
{
    a = ((a & 0x00000000000000FFULL) << 56) |
    ((a & 0x000000000000FF00ULL) << 40) |
    ((a & 0x0000000000FF0000ULL) << 24) |
    ((a & 0x00000000FF000000ULL) <<  8) |
    ((a & 0x000000FF00000000ULL) >>  8) |
    ((a & 0x0000FF0000000000ULL) >> 24) |
    ((a & 0x00FF000000000000ULL) >> 40) |
    ((a & 0xFF00000000000000ULL) >> 56);
    return a;
}

typedef struct __BlobIndex {
    uint32_t type;                                  /* type of entry */
    uint32_t offset;                                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                                 /* magic number */
    uint32_t length;                                /* total length of SuperBlob */
    uint32_t count;                                 /* number of index entries following */
    CS_BlobIndex index[];                   /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

#define amfid_MISValidateSignatureAndCopyInfo_import_offset 0x4150

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                                /* total length of CodeDirectory blob */
    uint32_t version;                               /* compatibility version */
    uint32_t flags;                                 /* setup and mode flags */
    uint32_t hashOffset;                    /* offset of hash slot element at index zero */
    uint32_t identOffset;                   /* offset of identifier string */
    uint32_t nSpecialSlots;                 /* number of special hash slots */
    uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
    uint32_t codeLimit;                             /* limit to main image signature range */
    uint8_t hashSize;                               /* size of each hash in bytes */
    uint8_t hashType;                               /* type of hash (cdHashType* constants) */
    uint8_t spare1;                                 /* unused (must be zero) */
    uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

#define LC_CODE_SIGNATURE 0x1d  /* local of code signature */
char* get_binary_hash(char* filename)
{
    int fd = open(filename, 0);
    if (fd == -1)
    {
        printf("[-]\tFile [%s] not found!\n", filename);
        return 0;
    } else {
        struct stat stat;
        if (fstat(fd, &stat))
            printf("t[-]\tThere was an error getting the stat of the file!");
        void* header = malloc(stat.st_size);
        read(fd, header, stat.st_size);
        
        struct mach_header_64* hdr = (struct mach_header_64*)header;
        uint8_t* commands = (uint8_t*)(hdr+1);
        uint32_t ncmds = hdr->ncmds;
        printf("[+]\tGot Header with %d Load commands\n", hdr->ncmds);
        uint32_t i;
        for (i=0; i < ncmds; i++)
        {
            struct load_command* lc = (struct load_command*)commands;
            if (lc->cmd == LC_CODE_SIGNATURE)
            {
                struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
                printf("[+]\tfound LC_CODE_SIGNATURE blob at offset +0x%x\n", cs_cmd->dataoff);
                uint32_t* code_base = (uint32_t*)((uint64_t)header + (uint64_t)cs_cmd->dataoff);
                uint32_t magic = *code_base;
                uint32_t offset = bswap32(code_base[4]); //TODO this is janky, tie symbols to [4]
                uint32_t type = bswap32(code_base[3]); //TODO this is janky, tie symbols to [3]
                magic = bswap32(magic);
                printf("[+]\tGot BLOB, MAGIC: 0x%x, offset: %x, type: %x\n",
                       magic,
                       offset,
                       type);
                if (!strncmp((char *)code_base, "Apple Ce", 8)) //TODO properly handle signed code
                {
                    printf("[X]\tThis is already signed properly so let's let it do it's own thing\n");
                    return 0;
                } else {
                    CS_SuperBlob* sb = (CS_SuperBlob*)code_base;
                    
                    for (uint32_t i = 0; i < ntohl(sb->count); i++)
                    {
                        CS_BlobIndex* bi = &sb->index[i];
                        uint8_t* blob = ((uint8_t*)sb) + (htonl(bi->offset));
                        printf("[i]\t\tblob &    : 0x%16llx\n", (uint64_t)blob);
                        printf("[i]\t\t*blob+0x00: 0x%16llx\n", *(uint64_t *)(blob+0x0));
                        printf("[i]\t\t*blob+0x08: 0x%16llx\n", *(uint64_t *)(blob+0x8));
                        printf("[i]\t\t*blob+0x10: 0x%16llx\n", *(uint64_t *)(blob+0x10));
                        printf("[i]\t\t*blob+0x18: 0x%16llx\n", *(uint64_t *)(blob+0x18));
                        if (htonl(*(uint32_t*)blob) == 0xfade0c02) {
                            CS_CodeDirectory* cd = (CS_CodeDirectory*)blob;
                            printf("[+]\tfound code directory, length=0x%x\n", htonl(sb->length));
                            SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
                            sha256_init(ctx);
                            sha256_update(ctx, blob, htonl(cd->length));
                            char* ret = malloc(0x20);
                            sha256_final(ctx, (BYTE *)ret);
                            return ret;
                        }
                    }
                }
                return ((char*)header) + cs_cmd->dataoff;
            }
            commands += lc->cmdsize;
        }
        
    }
    close(fd);
    return 0;
}


void* amfid_exception_handler(void* arg){
    /*
     We're still not properly handling signed code, and once the jailbreak app get's backgrounded the
     exception handler fails, we need to figure out how to permanently stop amfid, and handle both
     signed and unsigned code
     
     Jan 5 06:57:18 nokia-388 kernel(AppleMobileFileIntegrity)[0] <Notice>: int _validateCodeDirectoryHashInDaemon(const char *, struct cs_blob *, unsigned int *, unsigned int *, int, bool, bool, char *): verify_code_directory returned 0x10004005
     */
    kill_thread_flag = 0;
    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    kern_return_t kr;
    for(;;){
        kern_return_t err;
        printf("[+]\t[e]\t[%d]\tcalling mach_msg to receive exception message from amfid\n", getpid());
        if (kill_thread_flag)
            break;
        err = mach_msg(msg,
                       MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, // no timeout
                       0,
                       size,
                       amfid_exception_port,
                       0,
                       0); // this blocks
        if(access("/tmp/kill_nerfbat", F_OK) != -1)
        {
            printf("[+]\t[e]\tDetected suicide file, ending thread and cleaning up for userspace process\n");
            kill_thread_flag = 1;
        }
        if (err != KERN_SUCCESS){
            printf("[+]\t[e]\t\terror receiving on exception port: %s\n", mach_error_string(err));
        } else {
            printf("[+]\t[e]\t\tgot exception message from amfid!\n");
            //dword_hexdump(msg, msg->msgh_size);
            
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            printf("[+]\t[e]\t\tsizeof(old_state)=0x%lx, sizeof(old_state)/4=0x%lx\n", sizeof(old_state), sizeof(old_state)/4);
            err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (err != KERN_SUCCESS){
                printf("[-]\t[e]\t\terror getting thread state: %s\n", mach_error_string(err));
                continue;
            }
            
            printf("[+]\t[e]\t\tgot thread state\n");
            //dword_hexdump((void*)&old_state, sizeof(old_state));
            
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            // get the filename pointed to by X25
            char* filename = rmem(task_port, new_state.__x[25], 1024);
            printf("[+]\t[e]\t\tgot filename for amfid request: %s\n", filename);
            if (strstr(filename, "NO IT IS NOT AN APP"))
            {
                printf("OK, we got a normal app coming from userspace\n");
                amfid_base = binary_load_address(task_port);
                printf("Jumping thread to 0x%llx\n", old_amfid_MISVSACI);
                new_state.__pc = old_amfid_MISVSACI;
            } else {
                // parse that macho file and do a SHA1 hash of the CodeDirectory
                // scratch that do a sha256
                char* cdhash;
                cdhash = get_binary_hash(filename); //I'm honestly surprised this works
                // it took like 2 days of kernel crashing, failure, and depression
                // thanks Oban 14yr whiskey!
                
                kr = mach_vm_write(task_port, old_state.__x[24], (vm_offset_t)cdhash, 0x14);
                if (kr==KERN_SUCCESS)
                {
                    printf("[+]\t[e]\t\twrote the cdhash into amfid\n");
                } else {
                    printf("[+]\t[e]\t\tunable to write the cdhash into amfid!!!\n");
                }
                
                // also need to write a 1 to [x20]
                w32(task_port, old_state.__x[20], 1);
                new_state.__pc = (old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere to continue
                //            int i;
                //            for (i=0; i< 33; i++)
                //                printf("[+]\t[e]\t\tx[%d] = 0x%llx\n", i, old_state.__x[i]);
                printf("[+]\t[e]\t\tOld PC: 0x%llx, New PC: 0x%llx\n", old_state.__pc, new_state.__pc);
                //            char * filenameTrimmed = strrchr(filename, '/') + 1;
                //            int pid = get_pid_from_name(filenameTrimmed);
                //            printf("[+]\t[e]\t\t[%s] is coming up as pid (%d)\n", filenameTrimmed, pid);
            }
            free(filename);
            
            // set the new thread state:
            //ARM_THREAD_STATE64
            err = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (err != KERN_SUCCESS) {
                printf("[+]\t[e]\t\tfailed to set new thread state %s\n", mach_error_string(err));
            } else {
                printf("[+]\t[e]\t\tset new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            // MACH_SEND_MSG|MACH_MSG_OPTION_NONE == 1 ???
            err = mach_msg(&reply.Head,
                           1,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            if (err != KERN_SUCCESS){
                printf("[-]\t[e]\tfailed to send the reply to the exception message %s\n", mach_error_string(err));
            } else{
                printf("[+]\t[e]\treplied to the amfid exception...\n");
            }
        }
    }
    return NULL;
}


int set_exception_handler(mach_port_t amfid_task_port){
    // allocate a port to receive exceptions on:
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &amfid_exception_port);
    mach_port_insert_right(mach_task_self(), amfid_exception_port, amfid_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    printf("[set_exception_handler]\t[%d]\tamfid_task_port = 0x%x\n", getpid(), amfid_task_port);
    printf("[set_exception_handler]\t[%d]\tamfid_exception_port = 0x%x\n", getpid(), amfid_exception_port);
    kern_return_t err = task_set_exception_ports(amfid_task_port,
                                                 EXC_MASK_ALL,
                                                 amfid_exception_port,
                                                 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,  // we want to receive a catch_exception_raise message with the thread port for the crashing thread
                                                 ARM_THREAD_STATE64);
    if (err != KERN_SUCCESS){
        printf("[-]\t[h]\t[%d]\terror setting amfid exception port: %s\n", getpid(), mach_error_string(err));
    } else {
        printf("[+]\t[h]\t[%d]\tset amfid exception port\n", getpid());
        // spin up a thread to handle exceptions:
        pthread_create(&exception_thread, NULL, amfid_exception_handler, NULL);
        return 0;
    }
    return 1;
}

uint64_t patch_amfid(){
    
    task_t amfid_task_port;
    pid_t pid = pid_for_name("amfid");
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &amfid_task_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task for pid %u!", pid);
        return -1;
    }
    set_exception_handler(amfid_task_port);
    printf("[+]\t[%d]\tabout to search for the binary load address\n", getpid());
    amfid_base = binary_load_address(amfid_task_port);
    printf("[i]\t[%d]\tamfid load address: 0x%llx\n", getpid(), amfid_base);
    uint64_t old_amfid_MISVSACI = 0;
    mach_vm_size_t sz;
    mach_vm_read_overwrite(amfid_task_port,
                           amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset,
                           8,
                           (mach_vm_address_t)&old_amfid_MISVSACI,
                           &sz);
    printf("[i]\t[%d]\t Saving off old jump table: 0x%llx\n", getpid(), old_amfid_MISVSACI);
    w64(amfid_task_port, amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset, 0x4141414141414140); // crashy
    return old_amfid_MISVSACI;
}

// unpatch amfid so that userland nerfbat can take over
int unpatch_amfid(uint64_t old_amfid_MISVSACI){
    
    task_t amfid_task_port;
    pid_t pid = pid_for_name("amfid");
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &amfid_task_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task for pid %u!", pid);
        return -1;
    }
    
    //mach_port_deallocate(mach_task_self(), amfid_exception_port);
    printf("[+]\tabout to search for the binary load address\n");
    amfid_base = binary_load_address(amfid_task_port);
    printf("[i]\tamfid load address: 0x%llx\n", amfid_base);
    w64(amfid_task_port, amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset, old_amfid_MISVSACI); // nocrashy
    return 0;
}

