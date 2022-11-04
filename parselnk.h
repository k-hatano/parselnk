
#include <stdio.h>
#include <stdlib.h>

#define BYTES_SIZE 4096

typedef struct {
    unsigned int localBaseIndex;
    unsigned int commonNetworkLinkIndex;
    unsigned int commonPathSuffixIndex;
} lnkIndexes;

lnkIndexes parseLnk(unsigned char *bytes, unsigned int filesize);
unsigned short bytesToShort(unsigned char *bytes, unsigned int index);
