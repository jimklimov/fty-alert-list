#include <czmq.h>
#include <fty_log.h>
#include <algorithm>

extern "C" {
#include <lualib.h>
#include <lauxlib.h>
}

#include "lua_evaluate.h"

DecoratorLuaEvaluate::~DecoratorLuaEvaluate ()
{
   if (lstate_) lua_close (lstate_);
}

void DecoratorLuaEvaluate::setGlobalVariables (const DecoratorLuaEvaluate::VariableMap vars)
{
    global_variables_.clear ();
    global_variables_ = vars;
    setGlobalVariablesToLUAStack ();
}

void DecoratorLuaEvaluate::setCode (const std::string newCode)
{
    if (lstate_) lua_close (lstate_);
    valid_ = false;
    code_.clear ();

#if LUA_VERSION_NUM > 501
    lstate_ = luaL_newstate ();
#else
    lstate_ = lua_open ();
#endif
    if (! lstate_) {
        throw std::runtime_error ("Can't initiate LUA context!");
    }
    luaL_openlibs (lstate_); // get functions like print ();

    // set global variables
    setGlobalVariablesToLUAStack ();

    // set code, try to compile it
    code_ = newCode;
    int error = luaL_dostring (lstate_, code_.c_str ());
    valid_ = (error == 0);
    if (! valid_) {
        throw std::runtime_error ("Invalid LUA code!");
    }

    // check wether there is main () function
    lua_getglobal (lstate_, "main");
    if (! lua_isfunction (lstate_, lua_gettop (lstate_))) {
        // main () missing
        valid_ = false;
        throw std::runtime_error ("Function main not found!");
    }
}

std::string DecoratorLuaEvaluate::evaluate (const std::vector<std::string> &metrics)
{
    std::string result;

    if (! valid_) { throw std::runtime_error ("Rule is not valid!"); }
    lua_settop (lstate_, 0);

    lua_getglobal (lstate_, "main");
    for (const auto x: metrics) {
        lua_pushstring (lstate_, x.c_str ());
    }
    if (lua_pcall (lstate_, metrics.size (), 1, 0) != 0) {
        throw std::runtime_error ("LUA calling main () failed!");
    }
    if (!lua_isstring (lstate_, -1)) {
        throw std::runtime_error ("LUA main function did not return string!");
    }
    result = lua_tostring (lstate_, -1);
    lua_pop (lstate_, 1);
    return result;
}

void DecoratorLuaEvaluate::setGlobalVariablesToLUAStack ()
{
    if (lstate_ == NULL) return;
    for (const auto &it : global_variables_ ) {
        lua_pushstring (lstate_, it.second.c_str ());
        lua_setglobal (lstate_, it.first.c_str ());
    }
}
