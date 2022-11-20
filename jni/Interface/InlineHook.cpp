#include <vector>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

extern "C"
{
    #include "Ihook.h"
}

void ModifyIBored() __attribute__((constructor));
void before_main() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //����HOOK��

void before_main() {
    LOGI("Hook is auto loaded!\n");
}

/**
 * External inline hook interface, responsible for managing inline hook information
 * @param pHookAddr the address to hook
 * @param onCallBack callback function to be inserted
 * @return inlinehook is set successfully (already set, repeated setting returns false)
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *))
{
    bool bRet = false;
    LOGI("InlineHook");

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }

    
    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 * External interface, used to cancel inline hook
 * @param pHookAddr The position to cancel the inline hook
 * @return Whether the cancellation is successful (if there is no return cancellation failure)
 */
bool UnInlineHook(void *pHookAddr)
{
    bool bRet = false;

    if(pHookAddr == NULL)
    {
        return bRet;
    }

    InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
    InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            gs_vecInlineHookInfo.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
            {
                delete *(pTargetInlineHookInfo->ppOldFuncAddr);
            }
            delete pTargetInlineHookInfo;
            bRet = true;
        }
    }

    return bRet;
}

/**
 * User-defined stub function, embedded in the hook point, can directly operate the register and change the logic operation of the game
 * Here the R0 register is locked to 0x333, a value much greater than 30
 * @param regs register structure, save the register information of the current hook point of the register
 */
void EvilHookStubFunctionForIBored(user_pt_regs *regs) //The parameter regs points to a data structure on the stack, which is passed by the second part of mov r0, sp
{
    LOGI("In Evil Hook Stub.");
    //regs->uregs[2] = 0x333; //regs->uregs[0]=0x333
    regs->regs[9]=0x333;
}

/**
 * For IBored applications, test functions that change game logic through inline hooks
 */
void ModifyIBored()
{
    LOGI("In IHook's ModifyIBored.");

    int target_offset = 0x600; //*��Hook��Ŀ����Ŀ��so�е�ƫ��*

    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libhellojni.so"); //Ŀ��so������

    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }
    
    uint64_t uiHookAddr = (uint64_t)pModuleBaseAddr + target_offset; //��ʵHook���ڴ��ַ

    
    InlineHook((void*)(uiHookAddr), EvilHookStubFunctionForIBored); //*The second parameter is the function processing function that Hook wants to insert*
}