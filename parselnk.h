
#include <stdio.h>
#include <stdlib.h>

#define BYTES_SIZE 1024

typedef struct {
    unsigned int localBaseIndex;
    unsigned int commonNetworkLinkIndex;
    unsigned int commonPathSuffixIndex;
} lnkIndexes;

void printContent(unsigned char *bytes, unsigned int filesize);
lnkIndexes parseLnk(unsigned char *bytes, unsigned int filesize);
unsigned short bytesToShort(unsigned char *bytes, unsigned int index);
unsigned long bytesToLong(unsigned char *bytes, unsigned int index);
void fixEndian(unsigned char *bytes, unsigned int index);

