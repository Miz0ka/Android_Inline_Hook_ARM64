#include "Ihook.h"
#include "fixPCOpcode.h"

#define ALIGN_PC(pc)	(pc & 0xFFFFFFFC)

/**
 * Modify page properties, change to readable, writable and executable
 * @param pAddress needs to modify the starting address of the attribute
 * @param size needs to modify the length of the page attribute, in byte
 * @return bool whether the modification is successful
 */
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;
    
    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return bRet;
    }
    
    //Calculate the number of pages included, align the starting address
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE); //get page size
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
    unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1); //pAddress & 0x1111 0000 0000 0000
    long lPageCount = (size / ulPageSize) + 1;
    
    long l = 0;
    while(l < lPageCount)
    {
        //Use mprotect to change page attributes
        int iRet = mprotect((const void *)(ulNewPageStartAddress), ulPageSize, iProtect);
        if(-1 == iRet)
        {
            LOGI("mprotect error:%s", strerror(errno));
            return bRet;
        }
        l++; 
    }
    
    return true;
}

/**
 * Obtain the module base address through /proc/$pid/maps
 * @param pid The pid of the process where the module is located. If accessing its own process, you can fill in a value less than 0, such as -1
 * @param pszModuleName module name
 * @return void* Module base address, return 0 if error
 */
void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};
    LOGI("first fork(): I'am father pid=%d", getpid());

    LOGI("Pid is %d\n",pid);

    //pid judgment, determine the maps file
    if (pid < 0)
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    }
    else
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath),  "/proc/%d/maps", pid);
    }

    pFileMaps = fopen(szMapFilePath, "r");
    if (NULL == pFileMaps)
    {
        return (void *)ulBaseValue;
    }
    LOGI("%d",pFileMaps);

    LOGI("Get map.\n");

    //Loop through the maps file, find the corresponding module, and intercept the address information
    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
    {
        //LOGI("%s\n",szFileLineBuffer);
        //LOGI("%s\n",pszModuleName);
        if (strstr(szFileLineBuffer, pszModuleName))
        {
            LOGI("%s\n",szFileLineBuffer);
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            if (pszModuleAddress)
            {
                ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

                if (ulBaseValue == 0x8000)
                    ulBaseValue = 0;

                break;
            }
        }
    }
    fclose(pFileMaps);
    return (void *)ulBaseValue;
}

/**
 * Inline hook basic information backup under arm (backup the original opcodes)
 * @param pstInlineHook inlinehook information
 * @return Whether the initialization information is successful
 */
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    uint32_t *currentOpcode = pstInlineHook->pHookAddr;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pstInlineHook->backUpFixLengthList[i] = -1;
    }
    LOGI("pstInlineHook->szbyBackupOpcodes is at %x",pstInlineHook->szbyBackupOpcodes);

    
    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    pstInlineHook->backUpLength = 24;
    
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, pstInlineHook->backUpLength);

    for(int i=0;i<6;i++){
        //currentOpcode += i; //GToad BUG
        LOGI("Arm64 Opcode to fix %d : %x",i,*currentOpcode);
        LOGI("Fix length : %d",lengthFixArm32(*currentOpcode));
        pstInlineHook->backUpFixLengthList[i] = lengthFixArm64(*currentOpcode);
        currentOpcode += 1; //GToad BUG
    }
    
    return true;
}

/**
  * Use the shellcode in ihookstub.s to construct a stub, jump to the pstInlineHook->onCallBack function, and call back the old function
  * @param pstInlineHook inlinehook information
  * @return whether the inlinehook pile is constructed successfully
 */
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;

        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        //malloc a new stub code
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        //Change the stub code page attribute to readable, writable and executable
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        //Set the jump to the external stub function
        LOGI("_hookstub_function_addr_s : %lx",p_hookstub_function_addr_s);
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        LOGI("ppHookStubFunctionAddr : %lx",ppHookStubFunctionAddr);
        LOGI("*ppHookStubFunctionAddr : %lx",*ppHookStubFunctionAddr);
        
        //Back up the function address pointer that jumps
        //after the external stub function is executed, and is used to fill the new address of the old function
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
            
        //Fill the shellcode address into hookinfo, which is used to construct the jump instruction of the hook point position
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;

        

        bRet = true;
        break;
    }
    
    return bRet;
}


/**
  * Construct and fill 32 jump instructions under ARM, need external guarantee to be readable and writable,
  * and pCurAddress must be at least 8 bytes in size
  * @param pCurAddress The current address, the position where the jump instruction is to be constructed
  * @param pJumpAddress destination address, the address to jump from the current position
  * @return whether the jump instruction is constructed successfully
 */
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    LOGI("LIVE4.3.1");
    bool bRet = false;
    while(1)
    {
        LOGI("LIVE4.3.2");
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }    
        LOGI("LIVE4.3.3");    
        //LDR PC, [PC, #-4]
        //addr
        //The machine code corresponding to LDR PC, [PC, #-4] is: 0xE51FF004
        //addr is the address to jump to. The range of the jump instruction is 32 bits, which is a full address jump for a 32-bit system.
        //Cache the constructed jump instruction (32 bits under ARM, two instructions only need 8 bytes)
        //BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};

        //STP X1, X0, [SP, #-0x10]
        //LDR X0, 8
        //BR X0
        //ADDR(64)
        //LDR X0, [SP, -0x8]
        BYTE szLdrPCOpcodes[24] = {0xe1, 0x03, 0x3f, 0xa9, 0x40, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6};
        //Copy destination address to jump instruction cache location
        memcpy(szLdrPCOpcodes + 12, &pJumpAddress, 8);
        szLdrPCOpcodes[20] = 0xE0;
        szLdrPCOpcodes[21] = 0x83;
        szLdrPCOpcodes[22] = 0x5F;
        szLdrPCOpcodes[23] = 0xF8;
        LOGI("LIVE4.3.4");
        
        //Brush the constructed jump instruction into it
        memcpy(pCurAddress, szLdrPCOpcodes, 24);
        LOGI("LIVE4.3.5");
        //__flush_cache(*((uint32_t*)pCurAddress), 20);
        //__builtin___clear_cache (*((uint64_t*)pCurAddress), *((uint64_t*)(pCurAddress+20)));
        //cacheflush(*((uint32_t*)pCurAddress), 20, 0);
        LOGI("LIVE4.3.6");
        bRet = true;
        break;
    }
    LOGI("LIVE4.3.7");
    return bRet;
}


/**
  * Construct the function header that was inline hooked, restore the original function header + add jump
  * Just copy and jump, and fill the old function address in the stub shellcode and the old function address in the hookinfo at the same time
  * This implementation has no command repair function, that is, the position command of HOOK cannot involve PC and other redirection commands
  * @param pstInlineHook inlinehook information
  * @return Whether the original function construction is successful
 */
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    void *fixOpcodes;
    int fixLength;
    LOGI("LIVE3.1");

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    LOGI("LIVE3.2");
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        LOGI("LIVE3.3");
        
        //8 bytes store the original opcodes, and the other 8 bytes store the jump instruction under the jump back hook point
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }
        LOGI("LIVE3.4");

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        LOGI("%x",pNewEntryForOldFunction);
        
        if(ChangePageProperty(pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        LOGI("LIVE3.5");
        
        fixLength = fixPCOpcodeArm(fixOpcodes, pstInlineHook); //Pass the starting address of the third part
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        LOGI("LIVE3.6");
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //fill jump instruction
        if(BuildArmJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength - 4) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("LIVE3.7");
        //Fill in the callback address of the stub in the shellcode
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        LOGI("LIVE3.8");
        
        bRet = true;
        break;
    }
    LOGI("LIVE3.9");
    
    return bRet;
}


    
/**
  * At the position to be HOOK, construct a jump and jump to the shellcode stub
  * @param pstInlineHook inlinehook information
  * @return Whether the in-place jump instruction is constructed successfully
 */
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        LOGI("LIVE4.1");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        LOGI("LIVE4.2");
        //Modify the page properties of the original location to ensure that it can be written
        if(ChangePageProperty(pstInlineHook->pHookAddr, 24) == false)
        {
            LOGI("change page property error.");
            break;
        }
        LOGI("LIVE4.3");
        //fill jump instruction
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("LIVE4.4");
        bRet = true;
        break;
    }
    LOGI("LIVE4.5");
    
    return bRet;
}


/**
  * inlinehook under ARM
  * @param pstInlineHook inlinehook information
  * @return inlinehook is set successfully
 */
bool HookArm(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    LOGI("HookArm()");
    
    while(1)
    {
        //LOGI("pstInlineHook is null 1.");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }
        LOGI("LIVE1");

        //LOGI("Init Arm HookInfo fail 1.");
        //Step 0, set the basic information of inline hook under ARM
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }
        LOGI("LIVE2");
        
        //LOGI("BuildStub fail 1.");
        //The second step is to construct a stub, the function is to save the state of the register, 
        //and at the same time jump to the target function, and then jump back to the original function
        //Need the target address, return the stub address, and also have the old pointer for subsequent filling
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        LOGI("LIVE3");
        
        //LOGI("BuildOldFunction fail 1.");
        //The fourth step is responsible for reconstructing the original function header,
        //the function is to repair the instruction, and the structure jumps back to the original address
        //Need the address of the original function
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }
        LOGI("LIVE4");
        
        //LOGI("RebuildHookAddress fail 1.");
        //The first step is to rewrite the original function header. The function is the last step to realize the inline hook, rewrite the jump
        //Cacheflush is required to prevent crashes
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("LIVE5");
        
        bRet = true;
        break;
    }
    LOGI("LIVE6");

    return bRet;
}


