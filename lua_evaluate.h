#ifndef __LUA_EVALUATE_GUARD__
#define __LUA_EVALUATE_GUARD__

#include <map>
#include <string>
#include <vector>
#include <cxxtools/serializationinfo.h>

extern "C" {
#include <lua.h>
}

class DecoratorLuaEvaluate {
    public:
        typedef std::map<std::string, std::string> VariableMap;
        typedef std::vector<std::string> VectorStrings;
    public:
        DecoratorLuaEvaluate () : outcome_items_(1) { };
        DecoratorLuaEvaluate (const DecoratorLuaEvaluate &r) : global_variables_ (r.global_variables_),
                code_ (r.code_), outcome_items_(1) { } ;
        /// get number of outcome variables (size of evaluation result)
        int getOutcomeItems () const { return outcome_items_; };
        /// get number of outcome variables (size of evaluation result)
        void setOutcomeItems (int count) { outcome_items_ = count; };
        /// get lua code
        std::string getCode () const { return code_; };
        /// set new code and reinitialize LUA stack
        void setCode (const std::string newCode);
        /// set global variables in lua code
        void setGlobalVariables (const VariableMap vars);
        VariableMap &getGlobalVariables () { return global_variables_; };
        /// evaluate code with respect to input arguments
        VectorStrings evaluate (const std::vector<std::string> &arguments);
        ~DecoratorLuaEvaluate ();
        //internal functions
    protected:
        /// global variables initialization in lua
        void setGlobalVariablesToLUAStack ();

        VariableMap global_variables_;
        bool valid_ = false;
        lua_State *lstate_ = NULL;
    private:
        /// plain code
        std::string code_;
        /// count of outcome elements
        int outcome_items_;
};

#endif // __lua_evaluate_guard__
