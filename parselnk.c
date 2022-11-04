
#include "parselnk.h"

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

lnkIndexes parseLnk(unsigned char *bytes, unsigned int filesize) {
    lnkIndexes result = {0, 0, 0};

    unsigned int i;
    unsigned int directoryFlag;
    unsigned char flags = bytes[0x14];

    unsigned int attributesIndex = 0x18;
    unsigned char attributes = bytes[attributesIndex];
    unsigned char directoryFlagMask = (unsigned char) 0x10;

    if ((attributes & directoryFlagMask) > 0) {
        directoryFlag = 1;
    } else {
        directoryFlag = 0;
    }

    unsigned int linkTargetIDIndex = 0x4c;
    unsigned int linkTargetIDSize = 0;
    if ((flags & 0x01) > 0) {
        linkTargetIDSize = bytesToShort(bytes, linkTargetIDIndex) + 2;
    }

    unsigned int lnkInfoIndex = linkTargetIDIndex + linkTargetIDSize;
    unsigned char hasLnkInfoMask = (unsigned char) 0x02;
    unsigned int lnkInfoSize = 0;

    if ((flags & hasLnkInfoMask) > 0) {
        lnkInfoSize = bytesToShort(bytes, lnkInfoIndex);
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
    }

    return result;
}

unsigned short bytesToShort(unsigned char *bytes, unsigned int index) {
    unsigned short result = ((bytes[index + 1] & 0xff) << 8) | (bytes[index] & 0xff);
    return result;
}

