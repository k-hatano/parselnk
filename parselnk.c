
#include "parselnk.h"

void printContent(unsigned char *bytes, unsigned int filesize);
lnkIndexes parseLnk(unsigned char *bytes, unsigned int filesize);
unsigned short bytesToShort(unsigned char *bytes, unsigned int index);
unsigned long bytesToLong(unsigned char *bytes, unsigned int index);
void fixEndian(unsigned char *bytes, unsigned int index);

int main(int args,  char** argv) {
    lnkIndexes result;
    unsigned char bytes[BYTES_SIZE];
    int byteAsInt;
    FILE *file;
    int filesize = 0;

    if (args < 2) {
        printf("Error : missing file name\n");
        return 1;
    }

    file = fopen(argv[1], "r");
    if (file == NULL) {
        printf("Error : failed opening file\n");
        return 1;
    }

    while ((byteAsInt = fgetc(file)) != EOF && filesize < BYTES_SIZE) {
        bytes[filesize] = (unsigned char)byteAsInt;
        filesize++;
    }

    result = parseLnk(bytes, filesize);

    fclose(file);

    return 0;
}

void printContent(unsigned char *bytes, unsigned int filesize) {
    int i;

    for (i = 0; i < filesize; i++) {
        printf("%02x ", bytes[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }
}

lnkIndexes parseLnk(unsigned char *bytes, unsigned int filesize) {
    lnkIndexes result = {0, 0, 0};

    unsigned int i;

    unsigned int directoryFlag;

    unsigned char flags = bytes[0x14];

    unsigned int attributesIndex = 0x18;
    unsigned char attributes = bytes[attributesIndex];
    unsigned char directoryFlagMask = (unsigned char) 0x10;

    printf("parseLnk\n");

    if ((attributes & directoryFlagMask) > 0) {
        directoryFlag = 1;
    } else {
        directoryFlag = 0;
    }

    printf("-- #0 shell link header --\n");

    printf("linkFlags = 0x%x\n", flags);

    printf(" %c  target ID list\n",    (flags & 0x01) > 0 ? 'o' : 'x');
    printf(" %c  link info\n",         (flags & 0x02) > 0 ? 'o' : 'x');
    printf(" %c  name\n",              (flags & 0x04) > 0 ? 'o' : 'x');
    printf(" %c  relative path\n",     (flags & 0x08) > 0 ? 'o' : 'x');
    printf(" %c  working dir\n",       (flags & 0x10) > 0 ? 'o' : 'x');
    printf(" %c  arguments\n",         (flags & 0x20) > 0 ? 'o' : 'x');
    printf(" %c  icon location\n",     (flags & 0x40) > 0 ? 'o' : 'x');
    printf(" %c  unicode\n",           (flags & 0x80) > 0 ? 'o' : 'x');

    printf("fileAttributes = 0x%x\n", attributes);

    printf(" %c  read only\n",    (attributes & 0x01) > 0 ? 'o' : 'x');
    printf(" %c  hidden\n",       (attributes & 0x02) > 0 ? 'o' : 'x');
    printf(" %c  system\n",       (attributes & 0x04) > 0 ? 'o' : 'x');
    printf(" %c  reserved1\n",    (attributes & 0x08) > 0 ? 'o' : 'x');
    printf(" %c  directory\n",    (attributes & 0x10) > 0 ? 'o' : 'x');
    printf(" %c  archive\n",      (attributes & 0x20) > 0 ? 'o' : 'x');
    printf(" %c  reserved2\n",    (attributes & 0x40) > 0 ? 'o' : 'x');
    printf(" %c  normal\n",       (attributes & 0x80) > 0 ? 'o' : 'x');
    printf(" %c  temporary\n",    (attributes & 0x100) > 0 ? 'o' : 'x');
    printf(" %c  sparse file\n",  (attributes & 0x200) > 0 ? 'o' : 'x');
    printf(" %c  compressed\n",   (attributes & 0x400) > 0 ? 'o' : 'x');
    printf(" %c  offline\n",      (attributes & 0x800) > 0 ? 'o' : 'x');
    printf(" %c  content unindexed\n", (attributes & 0x1000) > 0 ? 'o' : 'x');
    printf(" %c  encrypted\n",    (attributes & 0x2000) > 0 ? 'o' : 'x');

    unsigned int linkTargetIDIndex = 0x4c;
    unsigned int linkTargetIDSize = 0;
    if ((flags & 0x01) > 0) {
        linkTargetIDSize = bytesToShort(bytes, linkTargetIDIndex) + 2;
        printf("-- #%d link target list (size : %d) --\n", linkTargetIDIndex, linkTargetIDSize);
    }

    unsigned int lnkInfoIndex = linkTargetIDIndex + linkTargetIDSize;
    unsigned char hasLnkInfoMask = (unsigned char) 0x02;
    unsigned int lnkInfoSize = 0;

    if ((flags & hasLnkInfoMask) > 0) {
        lnkInfoSize = bytesToShort(bytes, lnkInfoIndex);
        printf("-- #%d link info (size : %d) --\n", lnkInfoIndex, lnkInfoSize);
    }

    unsigned int stringDataIndex = lnkInfoIndex + lnkInfoSize;

    if (lnkInfoSize > 0) {
        unsigned int localBaseIndexInBytes = 0x10;
        unsigned int commonNetworkLinkIndexInBytes = 0x14;
        unsigned int commonPathSuffixIndexInBytes = 0x18;
        unsigned int localBaseIndex = bytes[lnkInfoIndex + localBaseIndexInBytes] + lnkInfoIndex;
        unsigned int commonNetworkLinkIndex = bytes[lnkInfoIndex + commonNetworkLinkIndexInBytes] + lnkInfoIndex + 0x14;	
        unsigned int commonPathSuffixIndex = bytes[lnkInfoIndex + commonPathSuffixIndexInBytes] + lnkInfoIndex;

        result.localBaseIndex = bytes[lnkInfoIndex + localBaseIndexInBytes] > 0 ? localBaseIndex : 0;
        result.commonNetworkLinkIndex = bytes[lnkInfoIndex + commonNetworkLinkIndexInBytes] > 0 ? commonNetworkLinkIndex : 0;
        result.commonPathSuffixIndex = bytes[lnkInfoIndex + commonPathSuffixIndexInBytes] > 0 ? commonPathSuffixIndex : 0;
    }

    if (result.localBaseIndex > 0) {
        printf("localBase(#%d) = %s\n", result.localBaseIndex, &bytes[result.localBaseIndex]);
    } else {
        printf("localBase unavailable\n");
    }

    if (result.commonNetworkLinkIndex > 0) {
        printf("commonNetworkLink(#%d) = %s\n", result.commonNetworkLinkIndex, &bytes[result.commonNetworkLinkIndex]);
    } else {
        printf("commonNetworkLink unavailable\n");
    }

    if (result.commonPathSuffixIndex > 0) {
        printf("commonPathSuffix(#%d) = %s\n", result.commonPathSuffixIndex, &bytes[result.commonPathSuffixIndex]);
    } else {
        printf("commonPathSuffix unavailable\n");
    }

    printf("-- #%d string data --\n", stringDataIndex);
    if ((flags & 0x08) > 0) {
        printf("relativePath(#%d) = ", stringDataIndex);
        unsigned int relativePathIndex = stringDataIndex;
        unsigned int relativePathSize = bytes[stringDataIndex] * 2 + 2;
        for (i = relativePathIndex + 2; i < relativePathIndex + relativePathSize; i += 2) {
            if (bytes[i + 1] != 0) {
                printf("%c", bytes[i + 1]);
            }
            if (bytes[i] != 0) {
                printf("%c", bytes[i]);
            }
        }
        printf("\n");
        for (i = relativePathIndex + 2; i < relativePathIndex + relativePathSize; i += 2) {
            if (bytes[i] != 0) {
                printf("%c", bytes[i]);
            }
            if (bytes[i + 1] != 0) {
                printf("%c", bytes[i + 1]);
            }
        }
        printf("\n");
    }

    return result;
}

unsigned short bytesToShort(unsigned char *bytes, unsigned int index) {
    unsigned short result = ((bytes[index + 1] & 0xff) << 8) | (bytes[index] & 0xff);
    return result;
}

unsigned long bytesToLong(unsigned char *bytes, unsigned int index) {
    unsigned long result = 
    ((bytes[index + 3] & 0xff) << 24) | ((bytes[index + 2] & 0xff) << 16) | 
    ((bytes[index + 1] & 0xff) << 8) | (bytes[index] & 0xff);
    return result;
}

void fixEndian(unsigned char *bytes, unsigned int index) {
    unsigned int i = index;
    while (bytes[i] == 0) {
        if (bytes[i] > 0x80) {
            unsigned char tmp = bytes[i + 1];
            bytes[i + 1] = bytes[i];
            bytes[i] = tmp;
            i += 2;
        } else {
            i++;
        }
    }
}

