#ifndef fmy_h
#define fmy_h

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     *  fmy Encript
     *
     *@param inputFile input file path
     *
     *@param outputFile output file path
     *
     *@param key password
     *
     */
extern int fmy_Encript(const char *inputFile,const char *outputFile,const char *key);
    
    
    /**
     *  fmy Decript
     *
     *@param inputFile input file path
     *
     *@param outputFile output file path
     *
     *@param key password
     *
     */
extern int fmy_Decript(const char *inputFile,const char *outputFile,const char *key);
    
#ifdef __cplusplus
}
#endif

#endif
