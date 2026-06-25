/* mime.c */
#include <string.h>
#include "../include/httpd.h"

static const struct { const char *ext; const char *mime; } MIME_MAP[] = {
    {".html","text/html"},{".htm","text/html"},{".css","text/css"},
    {".js","application/javascript"},{".json","application/json"},
    {".png","image/png"},{".jpg","image/jpeg"},{".jpeg","image/jpeg"},
    {".gif","image/gif"},{".svg","image/svg+xml"},{".ico","image/x-icon"},
    {".pdf","application/pdf"},{".txt","text/plain"},{".xml","application/xml"},
    {".mp4","video/mp4"},{".mp3","audio/mpeg"},{".wasm","application/wasm"},
    {".zip","application/zip"},{".gz","application/gzip"},
    {NULL, NULL}
};

const char *mime_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    for (int i = 0; MIME_MAP[i].ext; i++)
        if (strcasecmp(dot, MIME_MAP[i].ext) == 0) return MIME_MAP[i].mime;
    return "application/octet-stream";
}
