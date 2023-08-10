#include <Windows.h>
#include <stdio.h>

#include "cepluginsdk.h"
#include "lua.h"

#include "callbacks.h"
#include "mylua.h"

#include "hook.h"
#include "DriverControl.h"

int               selfid;
ExportedFunctions Exported;
int               MainMenuPluginID = -1;

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    pv->version    = CESDK_VERSION;
    pv->pluginname = (char *)u8"香香CE增强插件 v2.0 (SDK version 4: 6.0+)";
    return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {

    MAINMENUPLUGIN_INIT initMainMenuAbout;
    MAINMENUPLUGIN_INIT initMainMenuProt;
    MAINMENUPLUGIN_INIT initMainMenuUnProt;
    selfid   = pluginid;
    Exported = *ef;
    if (Exported.sizeofExportedFunctions != sizeof(Exported))
        return FALSE;

    if (DriverControl::Instance().EnsureLoaded(L"XX_ACCESS.sys")) {
        MessageBoxW(NULL, L"驱动加载失败", L"错误", MB_OK);
        return FALSE;
    } else {
    }
    
    initMainMenuAbout.name            = (char *)u8"关于";
    initMainMenuAbout.callbackroutine = mainMenuAboutCallBack;
    initMainMenuAbout.shortcut        = NULL;

    initMainMenuProt.name            = (char *)u8"保护CE";
    initMainMenuProt.callbackroutine = []() { DriverControl::Instance().IOProtectProcess(GetCurrentProcessId()); };
    initMainMenuProt.shortcut        = NULL;

    initMainMenuUnProt.name            = (char *)u8"取消保护";
    initMainMenuUnProt.callbackroutine = []() { DriverControl::Instance().IOUnProtectProcess(GetCurrentProcessId()); };
    initMainMenuUnProt.shortcut        = NULL;

    Exported.RegisterFunction(pluginid, ptMainMenu, &initMainMenuAbout);
    Exported.RegisterFunction(pluginid, ptMainMenu, &initMainMenuProt);
    Exported.RegisterFunction(pluginid, ptMainMenu, &initMainMenuUnProt);

    lua_State *lua_state = ef->GetLuaState();
    lua_register(lua_state, "pluginExample", lua_pluginExample);
    lua_register(lua_state, "remoteCall", lua_remoteCall);
    lua_register(lua_state, "protectProc", lua_protectProc);
    return Attach();
}

BOOL __stdcall CEPlugin_DisablePlugin(void) {
    Detach();
    DriverControl::Instance().Unload();
    return true;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}