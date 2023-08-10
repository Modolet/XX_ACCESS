#include "mylua.h"
#include "DriverControl.h"
#include "cepluginsdk.h"

extern ExportedFunctions Exported;

int lua_pluginExample(lua_State *L) // make sure this is cdecl
{
    Exported.ShowMessage((char *)"Called from lua");
    lua_pushinteger(L, 123);
    return 1;
}

int lua_remoteCall(lua_State *L) {

    auto    pid     = *Exported.OpenedProcessID;
    ULONG64 address = luaL_checknumber(L, 1);
    ULONG64 retVal;
    if (pid == 0 || address == 0) {
        lua_pushinteger(L, -1);
    } else {

        double status = DriverControl::Instance().IORemoteCall((HANDLE)pid, address, &retVal);
        lua_pushinteger(L, retVal);
    }
    return 1;
}

int lua_protectProc(lua_State *L) {
    ULONG pid = luaL_checkinteger(L, 1);
    if (pid == 0) {
        lua_pushboolean(L, FALSE);
    }
    DriverControl::Instance().IOProtectProcess(pid);
    lua_pushboolean(L, TRUE);
    return 1;
}
