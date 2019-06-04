#ifndef __EXTENDED_RULE_GUARD__
#define __EXTENDED_RULE_GUARD__

#include <string>

#include "lua_evaluate.h"
#include "rule.h"

class SingleRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (const cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        SingleRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
                const VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        SingleRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        virtual ~SingleRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("single"); };
        virtual std::string evaluate (const VectorStrings &metrics);
};

class PatternRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (const cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        PatternRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
                const VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        PatternRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        virtual ~PatternRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("pattern"); };
        virtual std::string evaluate (const VectorStrings &metrics);
        bool metricNameMatchesPattern (std::string &metric_name);
};

class ThresholdRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void int saveToSerializedObject (const cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        ThresholdRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
                const VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        ThresholdRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        virtual ~ThresholdRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("threshold"); };
        virtual std::string evaluate (const VectorStrings &metrics);
};

#endif // __extended_rule_guard__
