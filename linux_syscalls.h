
#ifndef __LINUX_SYSCALLS
#define __LINUX_SYSCALLS

#define LINUX_SYS_EXIT 1
#define LINUX_SYS_FORK 2
#define LINUX_SYS_READ 3
#define LINUX_SYS_WRITE 4
#define LINUX_SYS_OPEN 5
#define LINUX_SYS_CLOSE 6
#define LINUX_SYS_WAITPID 7
#define LINUX_SYS_CREAT 8
#define LINUX_SYS_LINK 9
#define LINUX_SYS_UNLINK 10
#define LINUX_SYS_EXECVE 11
#define LINUX_SYS_CHDIR 12
#define LINUX_SYS_TIME 13
#define LINUX_SYS_MKNOD 14
#define LINUX_SYS_CHMOD 15
#define LINUX_SYS_LCHOWN 16
#define LINUX_SYS_BREAK 17
#define LINUX_SYS_OLDSTAT 18
#define LINUX_SYS_LSEEK 19
#define LINUX_SYS_GETPID 20
#define LINUX_SYS_MOUNT 21
#define LINUX_SYS_UMOUNT 22
#define LINUX_SYS_SETUID 23
#define LINUX_SYS_GETUID 24
#define LINUX_SYS_STIME 25
#define LINUX_SYS_PTRACE 26
#define LINUX_SYS_ALARM 27
#define LINUX_SYS_OLDFSTAT 28
#define LINUX_SYS_PAUSE 29
#define LINUX_SYS_UTIME 30
#define LINUX_SYS_STTY 31
#define LINUX_SYS_GTTY 32
#define LINUX_SYS_ACCESS 33
#define LINUX_SYS_NICE 34
#define LINUX_SYS_FTIME 35
#define LINUX_SYS_SYNC 36
#define LINUX_SYS_KILL 37
#define LINUX_SYS_RENAME 38
#define LINUX_SYS_MKDIR 39
#define LINUX_SYS_RMDIR 40
#define LINUX_SYS_DUP 41
#define LINUX_SYS_PIPE 42
#define LINUX_SYS_TIMES 43
#define LINUX_SYS_PROF 44
#define LINUX_SYS_BRK 45
#define LINUX_SYS_SETGID 46
#define LINUX_SYS_GETGID 47
#define LINUX_SYS_SIGNAL 48
#define LINUX_SYS_GETEUID 49
#define LINUX_SYS_GETEGID 50
#define LINUX_SYS_ACCT 51
#define LINUX_SYS_UMOUNT2 52
#define LINUX_SYS_LOCK 53
#define LINUX_SYS_IOCTL 54
#define LINUX_SYS_FCNTL 55
#define LINUX_SYS_MPX 56
#define LINUX_SYS_SETPGID 57
#define LINUX_SYS_ULIMIT 58
#define LINUX_SYS_OLDOLDUNAME 59
#define LINUX_SYS_UMASK 60
#define LINUX_SYS_CHROOT 61
#define LINUX_SYS_USTAT 62
#define LINUX_SYS_DUP2 63
#define LINUX_SYS_GETPPID 64
#define LINUX_SYS_GETPGRP 65
#define LINUX_SYS_SETSID 66
#define LINUX_SYS_SIGACTION 67
#define LINUX_SYS_SGETMASK 68
#define LINUX_SYS_SSETMASK 69
#define LINUX_SYS_SETREUID 70
#define LINUX_SYS_SETREGID 71
#define LINUX_SYS_SIGSUSPEND 72
#define LINUX_SYS_SIGPENDING 73
#define LINUX_SYS_SETHOSTNAME 74
#define LINUX_SYS_SETRLIMIT 75
#define LINUX_SYS_GETRLIMIT 76
#define LINUX_SYS_GETRUSAGE 77
#define LINUX_SYS_GETTIMEOFDAY 78
#define LINUX_SYS_SETTIMEOFDAY 79
#define LINUX_SYS_GETGROUPS 80
#define LINUX_SYS_SETGROUPS 81
#define LINUX_SYS_SELECT 82
#define LINUX_SYS_SYMLINK 83
#define LINUX_SYS_OLDLSTAT 84
#define LINUX_SYS_READLINK 85
#define LINUX_SYS_USELIB 86
#define LINUX_SYS_SWAPON 87
#define LINUX_SYS_REBOOT 88
#define LINUX_SYS_READDIR 89
#define LINUX_SYS_MMAP 90
#define LINUX_SYS_MUNMAP 91
#define LINUX_SYS_TRUNCATE 92
#define LINUX_SYS_FTRUNCATE 93
#define LINUX_SYS_FCHMOD 94
#define LINUX_SYS_FCHOWN 95
#define LINUX_SYS_GETPRIORITY 96
#define LINUX_SYS_SETPRIORITY 97
#define LINUX_SYS_PROFIL 98
#define LINUX_SYS_STATFS 99
#define LINUX_SYS_FSTATFS 100
#define LINUX_SYS_IOPERM 101
#define LINUX_SYS_SOCKETCALL 102
#define LINUX_SYS_SYSLOG 103
#define LINUX_SYS_SETITIMER 104
#define LINUX_SYS_GETITIMER 105
#define LINUX_SYS_STAT 106
#define LINUX_SYS_LSTAT 107
#define LINUX_SYS_FSTAT 108
#define LINUX_SYS_OLDUNAME 109
#define LINUX_SYS_IOPL 110
#define LINUX_SYS_VHANGUP 111
#define LINUX_SYS_IDLE 112
#define LINUX_SYS_VM86OLD 113
#define LINUX_SYS_WAIT4 114
#define LINUX_SYS_SWAPOFF 115
#define LINUX_SYS_SYSINFO 116
#define LINUX_SYS_IPC 117
#define LINUX_SYS_FSYNC 118
#define LINUX_SYS_SIGRETURN 119
#define LINUX_SYS_CLONE 120
#define LINUX_SYS_SETDOMAINNAME 121
#define LINUX_SYS_UNAME 122
#define LINUX_SYS_MODIFY_LDT 123
#define LINUX_SYS_ADJTIMEX 124
#define LINUX_SYS_MPROTECT 125
#define LINUX_SYS_SIGPROCMASK 126
#define LINUX_SYS_CREATE_MODULE 127
#define LINUX_SYS_INIT_MODULE 128
#define LINUX_SYS_DELETE_MODULE 129
#define LINUX_SYS_GET_KERNEL_SYMS 130
#define LINUX_SYS_QUOTACTL 131
#define LINUX_SYS_GETPGID 132
#define LINUX_SYS_FCHDIR 133
#define LINUX_SYS_BDFLUSH 134
#define LINUX_SYS_SYSFS 135
#define LINUX_SYS_PERSONALITY 136
#define LINUX_SYS_AFS_SYSCALL 137 
#define LINUX_SYS_SETFSUID 138
#define LINUX_SYS_SETFSGID 139
#define LINUX_SYS__LLSEEK 140
#define LINUX_SYS_GETDENTS 141
#define LINUX_SYS__NEWSELECT 142
#define LINUX_SYS_FLOCK 143
#define LINUX_SYS_MSYNC 144
#define LINUX_SYS_READV 145
#define LINUX_SYS_WRITEV 146
#define LINUX_SYS_GETSID 147
#define LINUX_SYS_FDATASYNC 148
#define LINUX_SYS__SYSCTL 149
#define LINUX_SYS_MLOCK 150
#define LINUX_SYS_MUNLOCK 151
#define LINUX_SYS_MLOCKALL 152
#define LINUX_SYS_MUNLOCKALL 153
#define LINUX_SYS_SCHED_SETPARAM 154
#define LINUX_SYS_SCHED_GETPARAM 155
#define LINUX_SYS_SCHED_SETSCHEDULER 156
#define LINUX_SYS_SCHED_GETSCHEDULER 157
#define LINUX_SYS_SCHED_YIELD 158
#define LINUX_SYS_SCHED_GET_PRIORITY_MAX 159
#define LINUX_SYS_SCHED_GET_PRIORITY_MIN 160
#define LINUX_SYS_SCHED_RR_GET_INTERVAL 161
#define LINUX_SYS_NANOSLEEP 162
#define LINUX_SYS_MREMAP 163
#define LINUX_SYS_SETRESUID 164
#define LINUX_SYS_GETRESUID 165
#define LINUX_SYS_VM86 166
#define LINUX_SYS_QUERY_MODULE 167
#define LINUX_SYS_POLL 168
#define LINUX_SYS_NFSSERVCTL 169
#define LINUX_SYS_SETRESGID 170
#define LINUX_SYS_GETRESGID 171
#define LINUX_SYS_PRCTL 172
#define LINUX_SYS_RT_SIGRETURN 173
#define LINUX_SYS_RT_SIGACTION 174
#define LINUX_SYS_RT_SIGPROCMASK 175
#define LINUX_SYS_RT_SIGPENDING 176
#define LINUX_SYS_RT_SIGTIMEDWAIT 177
#define LINUX_SYS_RT_SIGQUEUEINFO 178
#define LINUX_SYS_RT_SIGSUSPEND 179
#define LINUX_SYS_PREAD64 180
#define LINUX_SYS_PWRITE64 181
#define LINUX_SYS_CHOWN 182
#define LINUX_SYS_GETCWD 183
#define LINUX_SYS_CAPGET 184
#define LINUX_SYS_CAPSET 185
#define LINUX_SYS_SIGALTSTACK 186
#define LINUX_SYS_SENDFILE 187
#define LINUX_SYS_GETPMSG 188
#define LINUX_SYS_PUTPMSG 189
#define LINUX_SYS_VFORK 190
#define LINUX_SYS_UGETRLIMIT 191
#define LINUX_SYS_MMAP2 192
#define LINUX_SYS_TRUNCATE64 193
#define LINUX_SYS_FTRUNCATE64 194
#define LINUX_SYS_STAT64 195
#define LINUX_SYS_LSTAT64 196
#define LINUX_SYS_FSTAT64 197
#define LINUX_SYS_LCHOWN32 198
#define LINUX_SYS_GETUID32 199
#define LINUX_SYS_GETGID32 200
#define LINUX_SYS_GETEUID32 201
#define LINUX_SYS_GETEGID32 202
#define LINUX_SYS_SETREUID32 203
#define LINUX_SYS_SETREGID32 204
#define LINUX_SYS_GETGROUPS32 205
#define LINUX_SYS_SETGROUPS32 206
#define LINUX_SYS_FCHOWN32 207
#define LINUX_SYS_SETRESUID32 208
#define LINUX_SYS_GETRESUID32 209
#define LINUX_SYS_SETRESGID32 210
#define LINUX_SYS_GETRESGID32 211
#define LINUX_SYS_CHOWN32 212
#define LINUX_SYS_SETUID32 213
#define LINUX_SYS_SETGID32 214
#define LINUX_SYS_SETFSUID32 215
#define LINUX_SYS_SETFSGID32 216
#define LINUX_SYS_PIVOT_ROOT 217
#define LINUX_SYS_MINCORE 218
#define LINUX_SYS_MADVISE 219
#define LINUX_SYS_MADVISE1 219
#define LINUX_SYS_GETDENTS64 220
#define LINUX_SYS_FCNTL64 221
#define LINUX_SYS_GETTID 224
#define LINUX_SYS_READAHEAD 225
#define LINUX_SYS_SETXATTR 226
#define LINUX_SYS_LSETXATTR 227
#define LINUX_SYS_FSETXATTR 228
#define LINUX_SYS_GETXATTR 229
#define LINUX_SYS_LGETXATTR 230
#define LINUX_SYS_FGETXATTR 231
#define LINUX_SYS_LISTXATTR 232
#define LINUX_SYS_LLISTXATTR 233
#define LINUX_SYS_FLISTXATTR 234
#define LINUX_SYS_REMOVEXATTR 235
#define LINUX_SYS_LREMOVEXATTR 236
#define LINUX_SYS_FREMOVEXATTR 237
#define LINUX_SYS_TKILL 238
#define LINUX_SYS_SENDFILE64 239
#define LINUX_SYS_FUTEX 240
#define LINUX_SYS_SCHED_SETAFFINITY 241
#define LINUX_SYS_SCHED_GETAFFINITY 242
#define LINUX_SYS_SET_THREAD_AREA 243
#define LINUX_SYS_GET_THREAD_AREA 244
#define LINUX_SYS_IO_SETUP 245
#define LINUX_SYS_IO_DESTROY 246
#define LINUX_SYS_IO_GETEVENTS 247
#define LINUX_SYS_IO_SUBMIT 248
#define LINUX_SYS_IO_CANCEL 249
#define LINUX_SYS_FADVISE64 250
#define LINUX_SYS_EXIT_GROUP 252
#define LINUX_SYS_LOOKUP_DCOOKIE 253
#define LINUX_SYS_EPOLL_CREATE 254
#define LINUX_SYS_EPOLL_CTL 255
#define LINUX_SYS_EPOLL_WAIT 256
#define LINUX_SYS_REMAP_FILE_PAGES 257
#define LINUX_SYS_SET_TID_ADDRESS 258
#define LINUX_SYS_TIMER_CREATE 259
#define LINUX_SYS_TIMER_SETTIME (LINUX_SYS_TIMER_CREATE+1)
#define LINUX_SYS_TIMER_GETTIME (LINUX_SYS_TIMER_CREATE+2)
#define LINUX_SYS_TIMER_GETOVERRUN (LINUX_SYS_TIMER_CREATE+3)
#define LINUX_SYS_TIMER_DELETE (LINUX_SYS_TIMER_CREATE+4)
#define LINUX_SYS_CLOCK_SETTIME (LINUX_SYS_TIMER_CREATE+5)
#define LINUX_SYS_CLOCK_GETTIME (LINUX_SYS_TIMER_CREATE+6)
#define LINUX_SYS_CLOCK_GETRES (LINUX_SYS_TIMER_CREATE+7)
#define LINUX_SYS_CLOCK_NANOSLEEP (LINUX_SYS_TIMER_CREATE+8)
#define LINUX_SYS_STATFS64 268
#define LINUX_SYS_FSTATFS64 269
#define LINUX_SYS_TGKILL 270
#define LINUX_SYS_UTIMES 271
#define LINUX_SYS_FADVISE64_64 272
#define LINUX_SYS_VSERVER 273
#define LINUX_SYS_MBIND 274
#define LINUX_SYS_GET_MEMPOLICY 275
#define LINUX_SYS_SET_MEMPOLICY 276
#define LINUX_SYS_MQ_OPEN 277
#define LINUX_SYS_MQ_UNLINK (LINUX_SYS_MQ_OPEN+1)
#define LINUX_SYS_MQ_TIMEDSEND (LINUX_SYS_MQ_OPEN+2)
#define LINUX_SYS_MQ_TIMEDRECEIVE (LINUX_SYS_MQ_OPEN+3)
#define LINUX_SYS_MQ_NOTIFY (LINUX_SYS_MQ_OPEN+4)
#define LINUX_SYS_MQ_GETSETATTR (LINUX_SYS_MQ_OPEN+5)
#define LINUX_SYS_KEXEC_LOAD 283
#define LINUX_SYS_WAITID 284
#define LINUX_SYS_SYS_SETALTROOT 285
#define LINUX_SYS_ADD_KEY 286
#define LINUX_SYS_REQUEST_KEY 287
#define LINUX_SYS_KEYCTL 288
#define LINUX_SYS_IOPRIO_SET 289
#define LINUX_SYS_IOPRIO_GET 290
#define LINUX_SYS_INOTIFY_INIT 291
#define LINUX_SYS_INOTIFY_ADD_WATCH 292
#define LINUX_SYS_INOTIFY_RM_WATCH 293
#define LINUX_SYS_MIGRATE_PAGES 294
#define LINUX_SYS_OPENAT 295
#define LINUX_SYS_MKDIRAT 296
#define LINUX_SYS_MKNODAT 297
#define LINUX_SYS_FCHOWNAT 298
#define LINUX_SYS_FUTIMESAT 299
#define LINUX_SYS_FSTATAT64 300
#define LINUX_SYS_UNLINKAT 301
#define LINUX_SYS_RENAMEAT 302
#define LINUX_SYS_LINKAT 303
#define LINUX_SYS_SYMLINKAT 304
#define LINUX_SYS_READLINKAT 305
#define LINUX_SYS_FCHMODAT 306
#define LINUX_SYS_FACCESSAT 307
#define LINUX_SYS_PSELECT6 308
#define LINUX_SYS_PPOLL 309
#define LINUX_SYS_UNSHARE 310
#define LINUX_SYS_SET_ROBUST_LIST 311
#define LINUX_SYS_GET_ROBUST_LIST 312
#define LINUX_SYS_SPLICE 313
#define LINUX_SYS_SYNC_FILE_RANGE 314
#define LINUX_SYS_TEE 315
#define LINUX_SYS_VMSPLICE 316
#define LINUX_SYS_MOVE_PAGES 317
#define LINUX_SYS_GETCPU 318
#define LINUX_SYS_EPOLL_PWAIT 319

#define LINUX_SOCKET_SOCKET 1
#define LINUX_SOCKET_BIND 2
#define LINUX_SOCKET_CONNECT 3
#define LINUX_SOCKET_LISTEN 4
#define LINUX_SOCKET_ACCEPT 5
#define LINUX_SOCKET_GETSOCKNAME 6
#define LINUX_SOCKET_GETPEERNAME 7
#define LINUX_SOCKET_SOCKETPAIR 8
#define LINUX_SOCKET_SEND 9
#define LINUX_SOCKET_RECV 10
#define LINUX_SOCKET_SENDTO 11
#define LINUX_SOCKET_RECVFROM 12
#define LINUX_SOCKET_SHUTDOWN 13
#define LINUX_SOCKET_SETSOCKOPT 14
#define LINUX_SOCKET_GETSOCKOPT 15
#define LINUX_SOCKET_SENDMSG 16
#define LINUX_SOCKET_RECVMSG 17

//error numbers
#define LINUX_EPERM            1      /* Operation not permitted */
#define LINUX_ENOENT           2      /* No such file or directory */
#define LINUX_ESRCH            3      /* No such process */
#define LINUX_EINTR            4      /* Interrupted system call */
#define LINUX_EIO              5      /* I/O error */
#define LINUX_ENXIO            6      /* No such device or address */
#define LINUX_E2BIG            7      /* Argument list too long */
#define LINUX_ENOEXEC          8      /* Exec format error */
#define LINUX_EBADF            9      /* Bad file number */
#define LINUX_ECHILD          10      /* No child processes */
#define LINUX_EAGAIN          11      /* Try again */
#define LINUX_ENOMEM          12      /* Out of memory */
#define LINUX_EACCES          13      /* Permission denied */
#define LINUX_EFAULT          14      /* Bad address */
#define LINUX_ENOTBLK         15      /* Block device required */
#define LINUX_EBUSY           16      /* Device or resource busy */
#define LINUX_EEXIST          17      /* File exists */
#define LINUX_EXDEV           18      /* Cross-device link */
#define LINUX_ENODEV          19      /* No such device */
#define LINUX_ENOTDIR         20      /* Not a directory */
#define LINUX_EISDIR          21      /* Is a directory */
#define LINUX_EINVAL          22      /* Invalid argument */
#define LINUX_ENFILE          23      /* File table overflow */
#define LINUX_EMFILE          24      /* Too many open files */
#define LINUX_ENOTTY          25      /* Not a typewriter */
#define LINUX_ETXTBSY         26      /* Text file busy */
#define LINUX_EFBIG           27      /* File too large */
#define LINUX_ENOSPC          28      /* No space left on device */
#define LINUX_ESPIPE          29      /* Illegal seek */
#define LINUX_EROFS           30      /* Read-only file system */
#define LINUX_EMLINK          31      /* Too many links */
#define LINUX_EPIPE           32      /* Broken pipe */
#define LINUX_EDOM            33      /* Math argument out of domain of func */
#define LINUX_ERANGE          34      /* Math result not representable */

#define LINUX_EDEADLK         35      /* Resource deadlock would occur */
#define LINUX_ENAMETOOLONG    36      /* File name too long */
#define LINUX_ENOLCK          37      /* No record locks available */
#define LINUX_ENOSYS          38      /* Function not implemented */
#define LINUX_ENOTEMPTY       39      /* Directory not empty */
#define LINUX_ELOOP           40      /* Too many symbolic links encountered */
#define LINUX_EWOULDBLOCK     EAGAIN  /* Operation would block */
#define LINUX_ENOMSG          42      /* No message of desired type */
#define LINUX_EIDRM           43      /* Identifier removed */
#define LINUX_ECHRNG          44      /* Channel number out of range */
#define LINUX_EL2NSYNC        45      /* Level 2 not synchronized */
#define LINUX_EL3HLT          46      /* Level 3 halted */
#define LINUX_EL3RST          47      /* Level 3 reset */
#define LINUX_ELNRNG          48      /* Link number out of range */
#define LINUX_EUNATCH         49      /* Protocol driver not attached */
#define LINUX_ENOCSI          50      /* No CSI structure available */
#define LINUX_EL2HLT          51      /* Level 2 halted */
#define LINUX_EBADE           52      /* Invalid exchange */
#define LINUX_EBADR           53      /* Invalid request descriptor */
#define LINUX_EXFULL          54      /* Exchange full */
#define LINUX_ENOANO          55      /* No anode */
#define LINUX_EBADRQC         56      /* Invalid request code */
#define LINUX_EBADSLT         57      /* Invalid slot */

#define LINUX_EDEADLOCK       LINUX_EDEADLK

#define LINUX_EBFONT          59      /* Bad font file format */
#define LINUX_ENOSTR          60      /* Device not a stream */
#define LINUX_ENODATA         61      /* No data available */
#define LINUX_ETIME           62      /* Timer expired */
#define LINUX_ENOSR           63      /* Out of streams resources */
#define LINUX_ENONET          64      /* Machine is not on the network */
#define LINUX_ENOPKG          65      /* Package not installed */
#define LINUX_EREMOTE         66      /* Object is remote */
#define LINUX_ENOLINK         67      /* Link has been severed */
#define LINUX_EADV            68      /* Advertise error */
#define LINUX_ESRMNT          69      /* Srmount error */
#define LINUX_ECOMM           70      /* Communication error on send */
#define LINUX_EPROTO          71      /* Protocol error */
#define LINUX_EMULTIHOP       72      /* Multihop attempted */
#define LINUX_EDOTDOT         73      /* RFS specific error */
#define LINUX_EBADMSG         74      /* Not a data message */
#define LINUX_EOVERFLOW       75      /* Value too large for defined data type */
#define LINUX_ENOTUNIQ        76      /* Name not unique on network */
#define LINUX_EBADFD          77      /* File descriptor in bad state */
#define LINUX_EREMCHG         78      /* Remote address changed */
#define LINUX_ELIBACC         79      /* Can not access a needed shared library */
#define LINUX_ELIBBAD         80      /* Accessing a corrupted shared library */
#define LINUX_ELIBSCN         81      /* .lib section in a.out corrupted */
#define LINUX_ELIBMAX         82      /* Attempting to link in too many shared libraries */
#define LINUX_ELIBEXEC        83      /* Cannot exec a shared library directly */
#define LINUX_EILSEQ          84      /* Illegal byte sequence */
#define LINUX_ERESTART        85      /* Interrupted system call should be restarted */
#define LINUX_ESTRPIPE        86      /* Streams pipe error */
#define LINUX_EUSERS          87      /* Too many users */
#define LINUX_ENOTSOCK        88      /* Socket operation on non-socket */
#define LINUX_EDESTADDRREQ    89      /* Destination address required */
#define LINUX_EMSGSIZE        90      /* Message too long */
#define LINUX_EPROTOTYPE      91      /* Protocol wrong type for socket */
#define LINUX_ENOPROTOOPT     92      /* Protocol not available */
#define LINUX_EPROTONOSUPPORT 93      /* Protocol not supported */
#define LINUX_ESOCKTNOSUPPORT 94      /* Socket type not supported */
#define LINUX_EOPNOTSUPP      95      /* Operation not supported on transport endpoint */
#define LINUX_EPFNOSUPPORT    96      /* Protocol family not supported */
#define LINUX_EAFNOSUPPORT    97      /* Address family not supported by protocol */
#define LINUX_EADDRINUSE      98      /* Address already in use */
#define LINUX_EADDRNOTAVAIL   99      /* Cannot assign requested address */
#define LINUX_ENETDOWN        100     /* Network is down */
#define LINUX_ENETUNREACH     101     /* Network is unreachable */
#define LINUX_ENETRESET       102     /* Network dropped connection because of reset */
#define LINUX_ECONNABORTED    103     /* Software caused connection abort */
#define LINUX_ECONNRESET      104     /* Connection reset by peer */
#define LINUX_ENOBUFS         105     /* No buffer space available */
#define LINUX_EISCONN         106     /* Transport endpoint is already connected */
#define LINUX_ENOTCONN        107     /* Transport endpoint is not connected */
#define LINUX_ESHUTDOWN       108     /* Cannot send after transport endpoint shutdown */
#define LINUX_ETOOMANYREFS    109     /* Too many references: cannot splice */
#define LINUX_ETIMEDOUT       110     /* Connection timed out */
#define LINUX_ECONNREFUSED    111     /* Connection refused */
#define LINUX_EHOSTDOWN       112     /* Host is down */
#define LINUX_EHOSTUNREACH    113     /* No route to host */
#define LINUX_EALREADY        114     /* Operation already in progress */
#define LINUX_EINPROGRESS     115     /* Operation now in progress */
#define LINUX_ESTALE          116     /* Stale NFS file handle */
#define LINUX_EUCLEAN         117     /* Structure needs cleaning */
#define LINUX_ENOTNAM         118     /* Not a XENIX named type file */
#define LINUX_ENAVAIL         119     /* No XENIX semaphores available */
#define LINUX_EISNAM          120     /* Is a named type file */
#define LINUX_EREMOTEIO       121     /* Remote I/O error */
#define LINUX_EDQUOT          122     /* Quota exceeded */

#define LINUX_ENOMEDIUM       123     /* No medium found */
#define LINUX_EMEDIUMTYPE     124     /* Wrong medium type */
#define LINUX_ECANCELED       125     /* Operation Canceled */
#define LINUX_ENOKEY          126     /* Required key not available */
#define LINUX_EKEYEXPIRED     127     /* Key has expired */
#define LINUX_EKEYREVOKED     128     /* Key has been revoked */
#define LINUX_EKEYREJECTED    129     /* Key was rejected by service */

/* for robust mutexes */
#define LINUX_EOWNERDEAD      130     /* Owner died */
#define LINUX_ENOTRECOVERABLE 131     /* State not recoverable */

#define LINUX_ERFKILL         132     /* Operation not possible due to RF-kill */

#define GDT_ENTRY_TLS_MIN 6
#define GDT_ENTRY_TLS_MAX 8

#endif
