#include "callbacks.h"
#include "cepluginsdk.h"

extern ExportedFunctions Exported;
void __stdcall mainMenuAboutCallBack(void) {
    Exported.ShowMessage((char *)u8"香香CE驱动增强插件.\n提过lua接口remoteCall(call地址,参数...)");
    return;
}