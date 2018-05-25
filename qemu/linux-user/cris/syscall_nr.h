/*
 * This file contains the system call numbers, and stub macros for libc.
 */

#define TARGET_NR_restart_syscall      0
#define TARGET_NR_exit		  1
#define TARGET_NR_fork		  2
#define TARGET_NR_read		  3
#define TARGET_NR_write		  4
#define TARGET_NR_open		  5
#define TARGET_NR_close		  6
#define TARGET_NR_waitpid		  7
#define TARGET_NR_creat		  8
#define TARGET_NR_link		  9
#define TARGET_NR_unlink		 10
#define TARGET_NR_execve		 11
#define TARGET_NR_chdir		 12
#define TARGET_NR_time		 13
#define TARGET_NR_mknod		 14
#define TARGET_NR_chmod		 15
#define TARGET_NR_lchown		 16
#define TARGET_NR_break		 17
#define TARGET_NR_oldstat		 18
#define TARGET_NR_lseek		 19
#define TARGET_NR_getpid		 20
#define TARGET_NR_mount		 21
#define TARGET_NR_umount		 22
#define TARGET_NR_setuid		 23
#define TARGET_NR_getuid		 24
#define TARGET_NR_stime		 25
#define TARGET_NR_ptrace		 26
#define TARGET_NR_alarm		 27
#define TARGET_NR_oldfstat		 28
#define TARGET_NR_pause		 29
#define TARGET_NR_utime		 30
#define TARGET_NR_stty		 31
#define TARGET_NR_gtty		 32
#define TARGET_NR_access		 33
#define TARGET_NR_nice		 34
#define TARGET_NR_ftime		 35
#define TARGET_NR_sync		 36
#define TARGET_NR_kill		 37
#define TARGET_NR_rename		 38
#define TARGET_NR_mkdir		 39
#define TARGET_NR_rmdir		 40
#define TARGET_NR_dup		 41
#define TARGET_NR_pipe		 42
#define TARGET_NR_times		 43
#define TARGET_NR_prof		 44
#define TARGET_NR_brk		 45
#define TARGET_NR_setgid		 46
#define TARGET_NR_getgid		 47
#define TARGET_NR_signal		 48
#define TARGET_NR_geteuid		 49
#define TARGET_NR_getegid		 50
#define TARGET_NR_acct		 51
#define TARGET_NR_umount2		 52
#define TARGET_NR_lock		 53
#define TARGET_NR_ioctl		 54
#define TARGET_NR_fcntl		 55
#define TARGET_NR_mpx		 56
#define TARGET_NR_setpgid		 57
#define TARGET_NR_ulimit		 58
#define TARGET_NR_oldolduname	 59
#define TARGET_NR_umask		 60
#define TARGET_NR_chroot		 61
#define TARGET_NR_ustat		 62
#define TARGET_NR_dup2		 63
#define TARGET_NR_getppid		 64
#define TARGET_NR_getpgrp		 65
#define TARGET_NR_setsid		 66
#define TARGET_NR_sigaction		 67
#define TARGET_NR_sgetmask		 68
#define TARGET_NR_ssetmask		 69
#define TARGET_NR_setreuid		 70
#define TARGET_NR_setregid		 71
#define TARGET_NR_sigsuspend		 72
#define TARGET_NR_sigpending		 73
#define TARGET_NR_sethostname	 74
#define TARGET_NR_setrlimit		 75
#define TARGET_NR_getrlimit		 76
#define TARGET_NR_getrusage		 77
#define TARGET_NR_gettimeofday	 78
#define TARGET_NR_settimeofday	 79
#define TARGET_NR_getgroups		 80
#define TARGET_NR_setgroups		 81
#define TARGET_NR_select		 82
#define TARGET_NR_symlink		 83
#define TARGET_NR_oldlstat		 84
#define TARGET_NR_readlink		 85
#define TARGET_NR_uselib		 86
#define TARGET_NR_swapon		 87
#define TARGET_NR_reboot		 88
#define TARGET_NR_readdir		 89
#define TARGET_NR_mmap		 90
#define TARGET_NR_munmap		 91
#define TARGET_NR_truncate		 92
#define TARGET_NR_ftruncate		 93
#define TARGET_NR_fchmod		 94
#define TARGET_NR_fchown		 95
#define TARGET_NR_getpriority	 96
#define TARGET_NR_setpriority	 97
#define TARGET_NR_profil		 98
#define TARGET_NR_statfs		 99
#define TARGET_NR_fstatfs		100
#define TARGET_NR_ioperm		101
#define TARGET_NR_socketcall		102
#define TARGET_NR_syslog		103
#define TARGET_NR_setitimer		104
#define TARGET_NR_getitimer		105
#define TARGET_NR_stat		106
#define TARGET_NR_lstat		107
#define TARGET_NR_fstat		108
#define TARGET_NR_olduname		109
#define TARGET_NR_iopl		110
#define TARGET_NR_vhangup		111
#define TARGET_NR_idle		112
#define TARGET_NR_vm86		113
#define TARGET_NR_wait4		114
#define TARGET_NR_swapoff		115
#define TARGET_NR_sysinfo		116
#define TARGET_NR_ipc		117
#define TARGET_NR_fsync		118
#define TARGET_NR_sigreturn		119
#define TARGET_NR_clone		120
#define TARGET_NR_setdomainname	121
#define TARGET_NR_uname		122
#define TARGET_NR_modify_ldt		123
#define TARGET_NR_adjtimex		124
#define TARGET_NR_mprotect		125
#define TARGET_NR_sigprocmask	126
#define TARGET_NR_create_module	127
#define TARGET_NR_init_module	128
#define TARGET_NR_delete_module	129
#define TARGET_NR_get_kernel_syms	130
#define TARGET_NR_quotactl		131
#define TARGET_NR_getpgid		132
#define TARGET_NR_fchdir		133
#define TARGET_NR_bdflush		134
#define TARGET_NR_sysfs		135
#define TARGET_NR_personality	136
#define TARGET_NR_afs_syscall	137 /* Syscall for Andrew File System */
#define TARGET_NR_setfsuid		138
#define TARGET_NR_setfsgid		139
#define TARGET_NR__llseek		140
#define TARGET_NR_getdents		141
#define TARGET_NR__newselect		142
#define TARGET_NR_flock		143
#define TARGET_NR_msync		144
#define TARGET_NR_readv		145
#define TARGET_NR_writev		146
#define TARGET_NR_getsid		147
#define TARGET_NR_fdatasync		148
#define TARGET_NR__sysctl		149
#define TARGET_NR_mlock		150
#define TARGET_NR_munlock		151
#define TARGET_NR_mlockall		152
#define TARGET_NR_munlockall		153
#define TARGET_NR_sched_setparam		154
#define TARGET_NR_sched_getparam		155
#define TARGET_NR_sched_setscheduler		156
#define TARGET_NR_sched_getscheduler		157
#define TARGET_NR_sched_yield		158
#define TARGET_NR_sched_get_priority_max	159
#define TARGET_NR_sched_get_priority_min	160
#define TARGET_NR_sched_rr_get_interval	161
#define TARGET_NR_nanosleep		162
#define TARGET_NR_mremap		163
#define TARGET_NR_setresuid		164
#define TARGET_NR_getresuid		165

#define TARGET_NR_query_module	167
#define TARGET_NR_poll		168
#define TARGET_NR_nfsservctl		169
#define TARGET_NR_setresgid		170
#define TARGET_NR_getresgid		171
#define TARGET_NR_prctl              172
#define TARGET_NR_rt_sigreturn	173
#define TARGET_NR_rt_sigaction	174
#define TARGET_NR_rt_sigprocmask	175
#define TARGET_NR_rt_sigpending	176
#define TARGET_NR_rt_sigtimedwait	177
#define TARGET_NR_rt_sigqueueinfo	178
#define TARGET_NR_rt_sigsuspend	179
#define TARGET_NR_pread64		180
#define TARGET_NR_pwrite64		181
#define TARGET_NR_chown		182
#define TARGET_NR_getcwd		183
#define TARGET_NR_capget		184
#define TARGET_NR_capset		185
#define TARGET_NR_sigaltstack	186
#define TARGET_NR_sendfile		187
#define TARGET_NR_getpmsg		188	/* some people actually want streams */
#define TARGET_NR_putpmsg		189	/* some people actually want streams */
#define TARGET_NR_vfork		190
#define TARGET_NR_ugetrlimit		191	/* SuS compliant getrlimit */
#define TARGET_NR_mmap2		192
#define TARGET_NR_truncate64		193
#define TARGET_NR_ftruncate64	194
#define TARGET_NR_stat64		195
#define TARGET_NR_lstat64		196
#define TARGET_NR_fstat64		197
#define TARGET_NR_lchown32		198
#define TARGET_NR_getuid32		199
#define TARGET_NR_getgid32		200
#define TARGET_NR_geteuid32		201
#define TARGET_NR_getegid32		202
#define TARGET_NR_setreuid32		203
#define TARGET_NR_setregid32		204
#define TARGET_NR_getgroups32	205
#define TARGET_NR_setgroups32	206
#define TARGET_NR_fchown32		207
#define TARGET_NR_setresuid32	208
#define TARGET_NR_getresuid32	209
#define TARGET_NR_setresgid32	210
#define TARGET_NR_getresgid32	211
#define TARGET_NR_chown32		212
#define TARGET_NR_setuid32		213
#define TARGET_NR_setgid32		214
#define TARGET_NR_setfsuid32		215
#define TARGET_NR_setfsgid32		216
#define TARGET_NR_pivot_root		217
#define TARGET_NR_mincore		218
#define TARGET_NR_madvise		219
#define TARGET_NR_getdents64		220
#define TARGET_NR_fcntl64		221
/* 223 is unused */
#define TARGET_NR_gettid             224
#define TARGET_NR_readahead          225
#define TARGET_NR_setxattr		226
#define TARGET_NR_lsetxattr		227
#define TARGET_NR_fsetxattr		228
#define TARGET_NR_getxattr		229
#define TARGET_NR_lgetxattr		230
#define TARGET_NR_fgetxattr		231
#define TARGET_NR_listxattr		232
#define TARGET_NR_llistxattr		233
#define TARGET_NR_flistxattr		234
#define TARGET_NR_removexattr	235
#define TARGET_NR_lremovexattr	236
#define TARGET_NR_fremovexattr	237
#define TARGET_NR_tkill		238
#define TARGET_NR_sendfile64		239
#define TARGET_NR_futex		240
#define TARGET_NR_sched_setaffinity	241
#define TARGET_NR_sched_getaffinity	242
#define TARGET_NR_set_thread_area	243
#define TARGET_NR_get_thread_area	244
#define TARGET_NR_io_setup		245
#define TARGET_NR_io_destroy		246
#define TARGET_NR_io_getevents	247
#define TARGET_NR_io_submit		248
#define TARGET_NR_io_cancel		249
#define TARGET_NR_fadvise64		250
#define TARGET_NR_exit_group		252
#define TARGET_NR_lookup_dcookie	253
#define TARGET_NR_epoll_create	254
#define TARGET_NR_epoll_ctl		255
#define TARGET_NR_epoll_wait		256
#define TARGET_NR_remap_file_pages	257
#define TARGET_NR_set_tid_address	258
#define TARGET_NR_timer_create	259
#define TARGET_NR_timer_settime	(TARGET_NR_timer_create+1)
#define TARGET_NR_timer_gettime	(TARGET_NR_timer_create+2)
#define TARGET_NR_timer_getoverrun	(TARGET_NR_timer_create+3)
#define TARGET_NR_timer_delete	(TARGET_NR_timer_create+4)
#define TARGET_NR_clock_settime	(TARGET_NR_timer_create+5)
#define TARGET_NR_clock_gettime	(TARGET_NR_timer_create+6)
#define TARGET_NR_clock_getres	(TARGET_NR_timer_create+7)
#define TARGET_NR_clock_nanosleep	(TARGET_NR_timer_create+8)
#define TARGET_NR_statfs64		268
#define TARGET_NR_fstatfs64		269
#define TARGET_NR_tgkill		270
#define TARGET_NR_utimes		271
#define TARGET_NR_fadvise64_64	272
#define TARGET_NR_vserver		273
#define TARGET_NR_mbind		274
#define TARGET_NR_get_mempolicy	275
#define TARGET_NR_set_mempolicy	276
#define TARGET_NR_mq_open 		277
#define TARGET_NR_mq_unlink		(TARGET_NR_mq_open+1)
#define TARGET_NR_mq_timedsend	(TARGET_NR_mq_open+2)
#define TARGET_NR_mq_timedreceive	(TARGET_NR_mq_open+3)
#define TARGET_NR_mq_notify		(TARGET_NR_mq_open+4)
#define TARGET_NR_mq_getsetattr	(TARGET_NR_mq_open+5)
#define TARGET_NR_kexec_load		283
#define TARGET_NR_waitid		284
/* #define TARGET_NR_sys_setaltroot	285 */
#define TARGET_NR_add_key		286
#define TARGET_NR_request_key	287
#define TARGET_NR_keyctl		288
#define TARGET_NR_ioprio_set         289
#define TARGET_NR_ioprio_get         290
#define TARGET_NR_inotify_init       291
#define TARGET_NR_inotify_add_watch  292
#define TARGET_NR_inotify_rm_watch   293
#define TARGET_NR_migrate_pages      294
#define TARGET_NR_openat             295
#define TARGET_NR_mkdirat            296
#define TARGET_NR_mknodat            297
#define TARGET_NR_fchownat           298
#define TARGET_NR_futimesat          299
#define TARGET_NR_fstatat64          300
#define TARGET_NR_unlinkat           301
#define TARGET_NR_renameat           302
#define TARGET_NR_linkat             303
#define TARGET_NR_symlinkat          304
#define TARGET_NR_readlinkat         305
#define TARGET_NR_fchmodat           306
#define TARGET_NR_faccessat          307
#define TARGET_NR_pselect6           308
#define TARGET_NR_ppoll              309
#define TARGET_NR_unshare            310
#define TARGET_NR_set_robust_list    311
#define TARGET_NR_get_robust_list    312
#define TARGET_NR_splice             313
#define TARGET_NR_sync_file_range    314
#define TARGET_NR_tee                315
#define TARGET_NR_vmsplice           316
#define TARGET_NR_move_pages         317
#define TARGET_NR_getcpu             318
#define TARGET_NR_epoll_pwait        319
#define TARGET_NR_utimensat          320
#define TARGET_NR_signalfd           321
#define TARGET_NR_timerfd_create     322
#define TARGET_NR_eventfd            323
#define TARGET_NR_fallocate          324
#define TARGET_NR_timerfd_settime    325
#define TARGET_NR_timerfd_gettime    326
#define TARGET_NR_signalfd4          327
#define TARGET_NR_eventfd2           328
#define TARGET_NR_epoll_create1      329
#define TARGET_NR_dup3               330
#define TARGET_NR_pipe2              331
#define TARGET_NR_inotify_init1      332
