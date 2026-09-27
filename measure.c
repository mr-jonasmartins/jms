/* POSIX measurement helper: one child per invocation. Keeps Python's memory
 * footprint out of the child's pre-exec RSS high-water mark. Not part of JMS. */
/* Darwin hides BSD rusage fields (including ru_maxrss) in strict POSIX
 * mode. Request its public extensions before any system header. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
static double seconds(struct timespec t) { return (double)t.tv_sec+(double)t.tv_nsec/1e9; }
int main(int argc, char **argv) {
    struct timespec a,b;
    struct rusage r;
    pid_t child;
    int status;
    double rss;
    FILE *f;
    if(argc<3) return 2;
    if(clock_gettime(CLOCK_MONOTONIC,&a)) return 2;
    child=fork();
    if(child<0) return 2;
    if(child==0) { execvp(argv[2],argv+2); _exit(127); }
    while(waitpid(child,&status,0)<0) if(errno!=EINTR) return 2;
    if(clock_gettime(CLOCK_MONOTONIC,&b) || getrusage(RUSAGE_CHILDREN,&r)) return 2;
    if(!WIFEXITED(status) || WEXITSTATUS(status)) return 1;
#ifdef __APPLE__
    rss=(double)r.ru_maxrss/(1024.0*1024.0);
#else
    rss=(double)r.ru_maxrss/1024.0;
#endif
    f=fopen(argv[1],"w");
    if(!f) return 2;
    fprintf(f,"{\"seconds\":%.9f,\"user_seconds\":%.9f,\"system_seconds\":%.9f,\"peak_rss_mib\":%.9f}\n",
        seconds(b)-seconds(a), (double)r.ru_utime.tv_sec+(double)r.ru_utime.tv_usec/1e6,
        (double)r.ru_stime.tv_sec+(double)r.ru_stime.tv_usec/1e6,rss);
    return fclose(f)?2:0;
}
