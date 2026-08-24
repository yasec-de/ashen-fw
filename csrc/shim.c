#include <stddef.h>

#ifndef ASHEN_HOST_BUILD

void* _sbrk(int incr);
int   _write(int fd, const char* buf, int len);
int   _read(int fd, char* buf, int len);
int   _close(int fd);
int   _isatty(int fd);
int   _lseek(int fd, int ptr, int dir);
int   _fstat(int fd, void* st);
void  _exit(int code);
int   _kill(int pid, int sig);
int   _getpid(void);

extern int ashen_log_write(const char* buf, int len);

int _write(int fd, const char* buf, int len)
{
    (void)fd;
    return ashen_log_write(buf, len);
}

int _read(int fd, char* buf, int len)
{
    (void)fd;
    (void)buf;
    (void)len;
    return -1;
}

int _close(int fd)
{
    (void)fd;
    return -1;
}

int _isatty(int fd)
{
    (void)fd;
    return 0;
}

int _lseek(int fd, int ptr, int dir)
{
    (void)fd;
    (void)ptr;
    (void)dir;
    return -1;
}

int _fstat(int fd, void* st)
{
    (void)fd;
    (void)st;
    return -1;
}

int _kill(int pid, int sig)
{
    (void)pid;
    (void)sig;
    return -1;
}

int _getpid(void)
{
    return 1;
}

extern void ashen_c_panic(const char* msg);

void _exit(int code)
{
    (void)code;
    ashen_c_panic("libc _exit called from TPM core");
    for (;;) {
    }
}

void* _sbrk(int incr)
{
    (void)incr;
    return (void*)-1;
}

void __assert_func(const char* file, int line, const char* func, const char* expr)
{
    (void)file;
    (void)line;
    (void)func;
    (void)expr;
    ashen_c_panic("assertion failed in TPM core");
    for (;;) {
    }
}

#endif /* !ASHEN_HOST_BUILD */
