
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#include "fmy.h"

static int is_file_exists(const char* filename)
{
    struct stat buff;
    
    int err = stat( filename, &buff );
    if (err == -1 )
    {
        if (errno == ENOENT || errno == ENOTDIR)
        {
            return 0;
        }
    }
    return 1;
}
#pragma mark - FCR code
typedef struct tag_VerifyCode{
    unsigned int code0:32;  //8bytes
    unsigned int code1:32;  //8bytes
    unsigned int code2:32;  //8bytes
    unsigned int code3:32;  //8bytes
    unsigned int index:32;  //8bytes
}VerifyCode;

static void VCInit(VerifyCode *vcode)
{
    vcode->code0=0x12345678;
    vcode->code1=0x87654321;
    vcode->code2=0x12345678;
    vcode->code3=0x87654321;
    vcode->index=0;
}

static void VC2Str(unsigned char *str,VerifyCode vcode)
{
    *(str+0)=(vcode.code0)&0x000000FF;
    *(str+1)=(vcode.code0>>8)&0x000000FF;
    *(str+2)=(vcode.code0>>16)&0x000000FF;
    *(str+3)=(vcode.code0>>24)&0x000000FF;
    *(str+4)=(vcode.code1)&0x000000FF;
    *(str+5)=(vcode.code1>>8)&0x000000FF;
    *(str+6)=(vcode.code1>>16)&0x000000FF;
    *(str+7)=(vcode.code1>>24)&0x000000FF;
    *(str+8)=(vcode.code2)&0x000000FF;
    *(str+9)=(vcode.code2>>8)&0x000000FF;
    *(str+10)=(vcode.code2>>16)&0x000000FF;
    *(str+11)=(vcode.code2>>24)&0x000000FF;
    *(str+12)=(vcode.code3)&0x000000FF;
    *(str+13)=(vcode.code3>>8)&0x000000FF;
    *(str+14)=(vcode.code3>>16)&0x000000FF;
    *(str+15)=(vcode.code3>>24)&0x000000FF;
}

static int bit_count(unsigned char chr)
{
    int count=0;
    int tmp=((int)chr)&0x000000FF;
    
    while (tmp) {
        int left=tmp-1;
        tmp-=(left>>1);
        count++;
    }
    return count;
}

//vcode
static void VCDataUpdate(unsigned char *data,long length,VerifyCode *vcode)
{
    unsigned short index=vcode->index&0x0000FFFF;
    for (int i=0; i<length; i++) {
        //o = exchange 16bits
        unsigned int high16=(vcode->code0>>16)&0x0000FFFF;
        vcode->code0=vcode->code0<<16;
        vcode->code0|=high16;
        //c=data,index
        unsigned int code=(unsigned int)data[i]&0x00FF;
        code=code<<8;
        code |= (index&0x000000FF);
        //o^=c
        vcode->code0^=code&0x0000FFFF;
        
        //p = exchange 8bits
        high16=(vcode->code1>>8)&0x0000FFFF;
        vcode->code1=vcode->code1<<8;
        vcode->code1|=high16;
        //p+=data^index
        code=(unsigned int)data[i]&0x00FF;
        code ^= (index&0x000000FF);
        vcode->code1+=code;  //total
        
        high16=(vcode->code2>>8)&0x0000FFFF;
        vcode->code2=vcode->code2<<8;
        vcode->code2=high16;
        code=(unsigned int)data[i]&0x00FF;
        code ^= (0x000000FF);
        vcode->code2^=code;  //total
        
        
        high16=(vcode->code3>>8)&0x0000FFFF;
        vcode->code3=vcode->code3<<8;
        vcode->code3=high16;
        code=bit_count(data[i]);
        vcode->code3+=code;  //total
        
        index++;
    }
    vcode->index=index;
}

static void VCDataFinial(VerifyCode *vcode)
{
    vcode->code0^=(0x87654321^vcode->index);
    vcode->code1^=(0x12345678^vcode->index);
    vcode->code2^=0x87654321;
    vcode->code3^=0x12345678;
}

void FCRData(unsigned char *data,long length,unsigned char *codes)
{
    VerifyCode *vCode=(VerifyCode *)malloc(sizeof(VerifyCode));
    VCInit(vCode);
    if (length<1024)
    {
        unsigned char *buffer=(unsigned char *)malloc(2048);
        for (int i=0; i<2048; i+=length) {
            memcpy(buffer+i, data, length);
        }
        VCDataUpdate(buffer, 1024, vCode);
        free(buffer);
    }
    else
    {
        VCDataUpdate(data, length, vCode);
    }
    VCDataFinial(vCode);
    VC2Str(codes, *vCode);
    free(vCode);
}

int FCRFile(const char *file,unsigned char *codes)
{
    FILE *rfp=fopen(file, "rb");
    if (!rfp) {
        return -1;
    }
    fseek(rfp, 0, SEEK_END);
    long fileSize=ftell(rfp);
    fseek(rfp, 0, SEEK_SET);
    unsigned char buffer[1024]={0};
    if (fileSize<1024)
    {
        size_t len=fread(buffer, 1, 1024, rfp);
        FCRData(buffer, len, codes);
    }
    else
    {
        VerifyCode *vCode=(VerifyCode *)malloc(sizeof(VerifyCode));
        VCInit(vCode);
        while (1) {
            size_t len=fread(buffer, 1, 1024, rfp);
            VCDataUpdate(buffer, len, vCode);
            if (len<1024) {
                break;
            }
        }
        VCDataFinial(vCode);
        VC2Str(codes, *vCode);
        free(vCode);
    }
    fclose(rfp);
    return 0;
}

#pragma mark - RC4Y
static void RC4C_Swap(unsigned char *A,unsigned char *B)
{
    unsigned char tmp=*A;
    *A=*B;
    *B=tmp;
}

static void RC4C_Init(unsigned char *NumBox,const unsigned char *keyBytes, const char keyLength,unsigned RC4BoxLength)
{
    /*  产生数字系列和填充密码表  */
    unsigned char KeyBox[RC4BoxLength];
    memset(KeyBox, 0, RC4BoxLength);
    for (int i=0; i<RC4BoxLength; i++) {
        NumBox[i]=i;
        if (keyLength)
        {
            KeyBox[i]=keyBytes[i%keyLength];
        }
    }
    /*  打乱数字系列产生加密字符流(256bytes)  */
    int j=0;
    for (int i=0; i<RC4BoxLength; i++) {
        j=(j+NumBox[i]+KeyBox[i])%RC4BoxLength;
        RC4C_Swap(&NumBox[i], &NumBox[j]);
    }
}

static void RC4F_Rand(unsigned char *RBox,unsigned RC4BoxLength)
{
    /*  产生rand数字系列  */
    for (int i=0; i<RC4BoxLength; i++)
    {
        RBox[i]=(rand()+clock())%RC4BoxLength;
    }
}

#pragma mark - fmy

#define MAX_BUFFER_SIZE 1024

int fmy_Encript(const char *inputFile,const char *outputFile,const char *key)
{
    unsigned RC4BoxLength=256;
    if (!is_file_exists(inputFile))
    {
        return 0;
    }
    unsigned char NumBox[256]={0};
    RC4C_Init(NumBox, (const unsigned char *)key, strlen(key),RC4BoxLength);
    
    //fmz_
    unsigned char fileFlag[4]={'f','m','y',0};
    //data VCode
    unsigned char dataVCode[16]={0};
    FCRFile(inputFile, dataVCode);
    
    unsigned char RandLen=(rand()+clock())&0x00FF;
    if (RandLen<16)
    {
        RandLen+=16;    //256->128
    }
    fileFlag[3]=RandLen;
    unsigned char RBox[256]={0};
    RC4F_Rand(RBox, 256);
    
    unsigned char keyVCode[16]={0};
    FCRData((unsigned char *)key, strlen(key), keyVCode);
    
    //key VCode
    int k=0;
    int l=0;
    for (int i=0; i<RandLen; i++)
    {
        k=(i+1)%RC4BoxLength;
        l=(l+RBox[k%RandLen])%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
    }
    
    for (int i=0; i<16; i++) {
        k=i;
        l=dataVCode[i]%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
        dataVCode[i]^=RBox[i];
    }
    
    for (int i=0; i<16; i++) {
        k=i;
        l=keyVCode[i]%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
        keyVCode[i]^=RBox[i];
    }
    FILE *rfp=fopen(inputFile, "rb");
    if (!rfp) {
        return 0;
    }
    FILE *wfp=fopen(outputFile, "wb");
    if (!wfp) {
        fclose(rfp);
        return 0;
    }
    /* 对数据XOR加密 */
    unsigned char m=0,n=0;
    unsigned char t=0;
    unsigned char tmpChrs[MAX_BUFFER_SIZE];
    //1.header
    fwrite(fileFlag, 4, 1, wfp);
    //2.RandBox
    fwrite(RBox, RandLen, 1, wfp);
    //3.dataVCode^RandBox
    fwrite(dataVCode, 16, 1, wfp);
    //4.VCode(key+RandBox)
    unsigned char *mKeyData=(unsigned char *)malloc(strlen(key)+RandLen+2);
    memset(mKeyData, 0, strlen(key)+RandLen+2);
    memcpy(mKeyData, key, strlen(key));
    memcpy(mKeyData+strlen(key), RBox, RandLen);
    unsigned char newKeyVCode[16]={0};
    FCRData((unsigned char *)mKeyData, strlen(key)+RandLen, newKeyVCode);
    
    fwrite(newKeyVCode, 16, 1, wfp);
    free(mKeyData);
    while (1)
    {
        size_t len=fread(tmpChrs, 1, MAX_BUFFER_SIZE, rfp);
        if (len==0) {
            break;
        }
        for (int i=0; i<len; i++)
        {            
            m=(m+1)%RC4BoxLength;
            n=(n+NumBox[m])%RC4BoxLength;
            //RC4C_Swap(Sm,Sn);
            RC4C_Swap(&NumBox[m], &NumBox[n]);
            //t=(Sm+Sn)%RC4BoxLength
            t=(NumBox[m]+NumBox[n])%RC4BoxLength;
            tmpChrs[i]^=NumBox[t];
        }        
        fwrite(tmpChrs, len, 1, wfp);
    }
    
    fclose(rfp);
    fclose(wfp);
    
    return 1;
}

int fmy_Decript(const char *inputFile,const char *outputFile,const char *key)
{
    unsigned RC4BoxLength=256;
    if (!is_file_exists(inputFile)) {
        return 0;
    }
    FILE *rfp=fopen(inputFile, "rb");
    if (!rfp) {
        return 0;
    }
    FILE *wfp=fopen(outputFile, "wb");
    if (!wfp) {
        fclose(rfp);
        return 0;
    }
    unsigned char NumBox[256];
    RC4C_Init(NumBox, (const unsigned char *)key, strlen(key),RC4BoxLength);
    
    
    unsigned char fileHeader[3]={'f','m','y'};
    
    unsigned char fileFlag[4];
    fread(fileFlag, 4, 1, rfp);
    unsigned char Count=0;
    for (int i=0; i<3; i++)
    {
        Count+=fileHeader[i]^fileFlag[i];
        if (Count) {
            fclose(rfp);
            fclose(wfp);
            remove(outputFile);
            return 0;
        }
    }
    
    unsigned char RandLen=fileFlag[3]&0x00FF;
    unsigned char RBox[256]={0};
    
    fread(RBox, RandLen, 1, rfp);
    
    //data VCode
    unsigned char dataVCode[16]={0};
    
    fread(dataVCode, 16, 1, rfp);
    
    unsigned char newKeyVCode[16]={0};
    fread(newKeyVCode, 16, 1, rfp);
    
    unsigned char inputKeyVCode[16]={0};
    
    unsigned char *mKeyData=(unsigned char *)malloc(strlen(key)+RandLen+2);
    memset(mKeyData, 0, strlen(key)+RandLen+2);
    memcpy(mKeyData, key, strlen(key));
    memcpy(mKeyData+strlen(key), RBox, RandLen);
    FCRData((unsigned char *)mKeyData, strlen(key)+RandLen, inputKeyVCode);
    
    free(mKeyData);
    int count=0;
    for (int i=0; i<16; i++)
    {
        count+=(inputKeyVCode[i]^newKeyVCode[i]);
        if (count)
        {
            fclose(rfp);
            fclose(wfp);
            remove(outputFile);
            return 0;
        }
    }
    
    
    int k=0;
    int l=0;
    for (int i=0; i<RandLen; i++)
    {
        k=(i+1)%RC4BoxLength;
        l=(l+RBox[k%RandLen])%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
    }
    
    for (int i=0; i<16; i++) {
        dataVCode[i]^=RBox[i];
        k=i;
        l=dataVCode[i]%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
    }
    
    //key VCode
    unsigned char keyVCode[16]={0};
    FCRData((unsigned char *)key, strlen(key), keyVCode);
    
    for (int i=0; i<16; i++)
    {
        k=i;
        l=keyVCode[i]%RC4BoxLength;
        RC4C_Swap(&NumBox[k], &NumBox[l]);
    }
    
    /* 对数据XOR加密 */
    unsigned char m=0,n=0;
    unsigned char t=0;
    unsigned char tmpChrs[MAX_BUFFER_SIZE];
    
    while (1)
    {
        size_t len=fread(tmpChrs, 1, MAX_BUFFER_SIZE, rfp);
        if (len==0) {
            break;
        }
        for (int i=0; i<len; i++)
        {
            m=(m+1)%RC4BoxLength;
            n=(n+NumBox[m])%RC4BoxLength;
            //RC4C_Swap(Sm,Sn);
            RC4C_Swap(&NumBox[m], &NumBox[n]);
            //t=(Sm+Sn)%RC4BoxLength
            t=(NumBox[m]+NumBox[n])%RC4BoxLength;
            tmpChrs[i]^=NumBox[t];
        }
        fwrite(tmpChrs, len, 1, wfp);
    }
    
    fclose(rfp);
    fclose(wfp);
    
    unsigned char newDataVCode[16]={0};
    FCRFile(outputFile, newDataVCode);
    count=0;
    for (int i=0; i<16; i++)
    {
        count=(newDataVCode[i]^dataVCode[i]);
        if (count)
        {
            remove(outputFile);
            return 0;
        }
    }
    return 1;
}


