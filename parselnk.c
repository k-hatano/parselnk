
#include <stdio.h>
#include <stdlib.h>

#define BYTES_SIZE 1024

void printContent(unsigned char *bytes, unsigned int filesize);
void parseLnk(unsigned char *bytes, unsigned int filesize);
unsigned short bytesToShort(unsigned char *bytes, unsigned int index);
unsigned long bytesToLong(unsigned char *bytes, unsigned int index);
void fixEndian(unsigned char *bytes, unsigned int index);

int main(int args,  char** argv) {
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

	parseLnk(bytes, filesize);

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

void parseLnk(unsigned char *bytes, unsigned int filesize) {
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

    if ((flags & 0x01) > 0) {
    	printf("o  target ID list\n");
    } else {
    	printf("x  target ID list\n");
    }

    if ((flags & 0x02) > 0) {
    	printf("o  link info\n");
    } else {
    	printf("x  link info\n");
    }

    if ((flags & 0x04) > 0) {
    	printf("o  name\n");
    } else {
    	printf("x  name\n");
    }

    if ((flags & 0x08) > 0) {
    	printf("o  relative path\n");
    } else {
    	printf("x  relative path\n");
    }

    if ((flags & 0x10) > 0) {
    	printf("o  working dir\n");
    } else {
    	printf("x  working dir\n");
    }

    if ((flags & 0x14) > 0) {
    	printf("o  unicode\n");
    } else {
    	printf("x  unicode\n");
    }

    unsigned int linkTargetIDIndex = 0x4c;
    unsigned int linkTargetIDSize = 0;
    if ((flags & 0x01) > 0) {
    	linkTargetIDSize = bytesToShort(bytes, linkTargetIDIndex) + 2;
    	printf("lnkTargetIDList available (size : %d)\n", linkTargetIDSize);
    }

    unsigned int lnkInfoIndex = linkTargetIDIndex + linkTargetIDSize;
    unsigned char hasLnkInfoMask = (unsigned char) 0x02;
    unsigned int lnkInfoSize = 0;

    if ((flags & hasLnkInfoMask) > 0) {
        lnkInfoSize = bytesToLong(bytes, lnkInfoIndex) + 4;
        printf("lnkinfo available (size : %d)\n", lnkInfoSize);
    }

    unsigned int stringDataIndex = lnkInfoIndex + lnkInfoSize;

    printf("stringDataIndex = %d\n", stringDataIndex);
    if (lnkInfoSize > 0) {
    	unsigned int localBaseIndexInBytes = 0x10;
    	unsigned int commonNetworkLinkIndexInBytes = 0x14;
    	unsigned int filenameIndexInBytes = 0x18;
    	unsigned int localBaseIndex = bytes[lnkInfoIndex + localBaseIndexInBytes] + lnkInfoIndex;
    	unsigned int commonNetworkLinkIndex = bytes[lnkInfoIndex + commonNetworkLinkIndexInBytes + 8] + lnkInfoIndex;	
      unsigned int filenameIndex = bytes[lnkInfoIndex + filenameIndexInBytes] + lnkInfoIndex;

      printf("localBase(%d) = %s\n", localBaseIndex, &bytes[localBaseIndex]);
      printf("commonNetworkLink(%d) = %s\n", commonNetworkLinkIndex, &bytes[commonNetworkLinkIndex]);
      printf("filename(%d) = %s\n", filenameIndex, &bytes[filenameIndex]);
  }
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

