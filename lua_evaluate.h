#ifndef __LUA_EVALUATE_GUARD__
#define __LUA_EVALUATE_GUARD__

#include <map>
#include <string>
#include <vector>

extern "C" {
#include <lua.h>
}

class DecoratorLuaEvaluate {
    public:
        typedef std::map<std::string, std::string> VariableMap;
    public:
        DecoratorLuaEvaluate () {};
        DecoratorLuaEvaluate (const DecoratorLuaEvaluate &r) : global_variables_ (r.global_variables_),
                code_ (r.code_) { } ;
        /// gets lua code
        std::string getCode () const { return code_; };
        /// sets new code and reinitialize LUA stack
        void setCode (const std::string newCode);
        /// sets global variables in lua code
        void setGlobalVariables (const VariableMap vars);
        VariableMap &getGlobalVariables () { return global_variables_; };
        /// evaluate code with respect to input arguments
        std::string evaluate (const std::vector<std::string> &arguments);
        ~DecoratorLuaEvaluate ();
    protected:
        /// global variables initialization in lua
        void setGlobalVariablesToLUAStack ();

        VariableMap global_variables_;
        bool valid_ = false;
        lua_State *lstate_ = NULL;
    private:
        std::string code_;
};

#endif // __lua_evaluate_guard__
