//
//  main.c
//  fmy
//
//  Created by wonderidea on 3/22/17.
//  Copyright (c) 2017 wonderidea. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "fmy.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    int help_flag=1;
    if (argc>=5) {
        const char *inputFile=argv[1];
        const char *outputFile=argv[2];
        const char *key=argv[3];
        const char *mode=argv[4];
        if (strcmp(mode, "0")==0) {
            fmy_Encript(inputFile, outputFile, key);
            help_flag=0;
        }
        else if(strcmp(mode, "1")==0)
        {
            fmy_Decript(inputFile, outputFile, key);
            help_flag=0;
        }
    }
    if (help_flag) {
        printf("fmy Encript/Decript Usage:\n");
        printf("\n");
        printf("Encript:{exe} {input file} {output file} {password} 0\n");
        printf("\n");
        printf("Decript:{exe} {input file} {output file} {password} 1\n");
        printf("\n");
    }
    return 0;
}
