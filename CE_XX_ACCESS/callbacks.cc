#include "callbacks.h"
#include "cepluginsdk.h"

extern ExportedFunctions Exported;
void __stdcall mainMenuAboutCallBack(void) {
    Exported.ShowMessage((char *)u8"����CE������ǿ���.\n���lua�ӿ�remoteCall(call��ַ,����...)");
    return;
}