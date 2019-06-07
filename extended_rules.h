#ifndef __EXTENDED_RULE_GUARD__
#define __EXTENDED_RULE_GUARD__

#include <string>
#include <cxxtools/serializationinfo.h>
#include <vector>
#include <map>

#include "lua_evaluate.h"
#include "rule.h"

class SingleRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        SingleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
                const Rule::VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        SingleRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        SingleRule (const std::string json) : Rule (json) { };
        virtual ~SingleRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("single"); };
        virtual Rule::VectorStrings evaluate (const Rule::VectorStrings &metrics);
};

class PatternRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        PatternRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
                const Rule::VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        PatternRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        PatternRule (const std::string json) : Rule (json) { };
        virtual ~PatternRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("pattern"); };
        virtual Rule::VectorStrings evaluate (const Rule::VectorStrings &metrics);
        bool metricNameMatchesPattern (std::string &metric_name);
};

class ThresholdRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        ThresholdRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
                const Rule::VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        ThresholdRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        ThresholdRule (const std::string json) : Rule (json) { };
        virtual ~ThresholdRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("threshold"); };
        virtual Rule::VectorStrings evaluate (const Rule::VectorStrings &metrics);
};

class FlexibleRule : public Rule, public DecoratorLuaEvaluate {
    protected:
        /// store list of models for better matching
        Rule::VectorStrings models_;

        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        FlexibleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
                const Rule::VectorStrings categories, const ResultsMap results, std::string code,
                DecoratorLuaEvaluate::VariableMap variables);
        FlexibleRule (const cxxtools::SerializationInfo &si) : Rule (si) { loadFromSerializedObject (si); };
        FlexibleRule (const std::string json);
        virtual ~FlexibleRule () {};
        // virtual functions
        virtual std::string whoami () const { return std::string ("flexible"); };
        virtual Rule::VectorStrings evaluate (const Rule::VectorStrings &metrics);
};

#endif // __extended_rule_guard__
