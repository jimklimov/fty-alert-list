#include "extended_rules.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

SingleRule::SingleRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
        const VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

std::string SingleRule::evaluate (const VectorStrings &metrics) {
    return DecoratorLuaEvaluate::evaluate (metrics);
}

PatternRule::PatternRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
        const VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

std::string PatternRule::evaluate (const VectorStrings &metrics) {
    if (metrics.size () == 1) {
        VectorStrings vsmetrics (metrics);
        std::ostringstream pattern_name;
        for (auto it = metrics_.begin (); it != metrics_.end (); it++) {
            if (it != metrics_.begin ()) {
                pattern_name << ", ";
            }
            pattern_name << *it;
        }
        vsmetrics.insert (vsmetrics.begin (), pattern_name.str ());
        return DecoratorLuaEvaluate::evaluate (metrics);
    } else if (metrics.size () == 2) {
        // name of pattern expected as first argument
        return DecoratorLuaEvaluate::evaluate (metrics);
    } else {
        throw std::logic_error ("Invalid metrics count for pattern rule");
    }
}

ThresholdRule::ThresholdRule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
        const VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables);
        setCode (code);
    }
}

std::string ThresholdRule::evaluate (const VectorStrings &metrics) {
    if (metrics_.size () == 1) {
        // TODO: FIXME: fix this afwul hardcoded list
        if (stod (metrics[0], nullptr) <= stod (variables_["low_critical"], nullptr)) {
            return std::string ("low_critical");
        }
        if (stod (metrics[0], nullptr) <= stod (variables_["low_warning"], nullptr)) {
            return std::string ("low_warning");
        }
        if (stod (metrics[0], nullptr) >= stod (variables_["high_critical"], nullptr)) {
            return std::string ("high_critical");
        }
        if (stod (metrics[0], nullptr) >= stod (variables_["high_warning"], nullptr)) {
            return std::string ("high_warning");
        }
        return std::string ("ok");
    } else {
        return DecoratorLuaEvaluate::evaluate (metrics);
    }
}
