/* Make sure these types are defined */
#ifndef __u32
typedef unsigned char        __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
#endif

#ifndef NULL
#define NULL 0
#endif

#define sinline static inline __attribute__((__always_inline__))
#define mem_barrier asm volatile("": : :"memory")

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif
