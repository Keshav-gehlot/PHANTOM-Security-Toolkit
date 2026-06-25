/* logger.c — Apache Combined Log Format */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include "../include/httpd.h"

static FILE          *g_logfp = NULL;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

void logger_init(const char *path) {
    if (path && path[0]) {
        g_logfp = fopen(path, "a");
        if (!g_logfp) perror("logger fopen");
    }
}

void logger_access(const char *ip, const char *method, const char *uri,
                   int status, int bytes, const char *ua) {
    char timebuf[64];
    time_t t = time(NULL);
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S +0000", gmtime(&t));

    pthread_mutex_lock(&g_mutex);
    FILE *out = g_logfp ? g_logfp : stdout;
    fprintf(out, "%s - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n",
            ip, timebuf, method, uri, status, bytes, ua ? ua : "-");
    fflush(out);
    pthread_mutex_unlock(&g_mutex);
}

void logger_close(void) {
    if (g_logfp) { fclose(g_logfp); g_logfp = NULL; }
}
