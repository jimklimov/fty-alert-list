#ifndef __RULE_GUARD__
#define __RULE_GUARD__

#include <vector>
#include <string>
#include <map>
#include <memory>
#include <cassert>
#include <cxxtools/serializationinfo.h>
#include <fty_log.h>

//  1  - equals
//  0  - different
// -1  - error
int
utf8eq (const std::string& s1, const std::string& s2);

void
si_getValueUtf8 (const cxxtools::SerializationInfo& si, const std::string& member_name, std::string& result);

class InterfaceRule {
    public:
        typedef std::vector<std::string> VectorStrings;
        /// identifies rule type
        virtual std::string whoami () const = 0;
        /*
         * \brief Evaluates the rule
         *
         * \param[in] metrics - a list of necessary metrics for evaluation in order given by getTargetMetrics ()
         *
         * \return string result of evaluation
         * \throw std::exception in case of evaluation failure
         */
        virtual std::string evaluate (const VectorStrings &metrics) = 0;
        /// identifies rule with unique name
        std::string getName (void) const;
        /// returns a list of metrics in order in which evaluation expects them to be
        VectorStrings getTargetMetrics (void) const;
};

/// common features of various rules
class Rule : public InterfaceRule {
    public:
        /*
         * \brief Helper structure to store a possible outcome of rule evaluation
         *
         * Rule evaluation outcome has three values:
         * - actions
         * - severity // severity is detected automatically !!!! user cannot change it
         * - description
         */
        struct Outcome {
            VectorStrings _actions;
            std::string _severity;
            std::string _description;
        };
        typedef std::map<std::string, std::string> VariableMap;
        typedef std::map<std::string, Outcome> ResultsMap;
    protected:
        // internal data
        /// internal rule name, case sensitive, ascii only
        std::string name_;
        /// human readable rule name
        std::string description_;
        /// human readable info about this rule purpose like "internal temperature", used in UI to display values
        std::string class_;
        /// list of rule categories
        VectorStrings categories_;
        /// Vector of metrics to be evaluated
        VectorStrings metrics_;
        /// map of results that are outcomes of rule evaluation, case sensitive, default "ok" is always present
        ResultsMap results_;
        /// source of the rule (default Manual user input)
        std::string source_;
        /// assets on which this rule is applied
        VectorStrings assets_;
        /// count of outcome elements
        int outcome_items_;
        /// map of variables that are used in rule evaluation
        VariableMap variables_;
        // TODO: FIXME: do all values need to use same units?
        /// value unit
        std::string value_unit_;
        /// alert hierarchy
        std::string hierarchy_;

        //internal functions
        void loadFromSerializedObject (const cxxtools::SerializationInfo &si);
        void saveToSerializedObject (const cxxtools::SerializationInfo &si) const;
    public:
        // ctors, dtors, =
        Rule (const std::string name, const VectorStrings metrics, const VectorStrings assets,
                const VectorStrings categories, const ResultsMap results) : name_(name), categories_(categories),
                metrics_(metrics), results_(results), assets_(assets), outcome_items_(1) { };
        Rule (const cxxtools::SerializationInfo &si) { loadFromSerializedObject (si); };
        virtual ~Rule () {};
        // getters/setters
        /// get rule internal name
        std::string getName (void) const { return name_; }
        /// get rule description (shorter string for user)
        std::string getRuleDescription (void) const { return description_; }
        /// set rule description (shorter string for user)
        void setRuleDescription (const std::string rule_description) { description_ = rule_description; }
        /// get rule class (longer string for user)
        std::string getRuleClass (void) const { return class_; }
        /// set rule class (longer string for user)
        void setRuleClass (const std::string rule_class) { class_ = rule_class; }
        /// get rule element (asset)
        VectorStrings getAssets (void) const { return assets_; }
        /// returns a list of metrics in order in which evaluation expects them to be
        VectorStrings getTargetMetrics (void) const { return metrics_; };
        /// returns a list of categories that apply for the rule
        VectorStrings getCategories (void) const { return categories_; };
        /// returns a list of results that rule can publish
        ResultsMap getResults (void) const { return results_; };
        /// get global variable list
        void setGlobalVariables (const VariableMap vars);
        /// set global varible list
        VariableMap getGlobalVariables (void) const { return variables_; }
        /// get rule hierarchy location
        std::string getHierarchy () const { return hierarchy_; };
        /// set rule hierarchy location
        void setHierarchy (const std::string hierarchy) { hierarchy_ = hierarchy; };
        // handling
        /// checks if rule has the same name as this rule
        bool hasSameNameAs (const std::unique_ptr<Rule> &rule) const { return hasSameNameAs (rule->name_); };
        /// checks if provided name matches this rule
        bool hasSameNameAs (const std::string &name) const { return utf8eq (name_, name); };
        /*
         * \brief Gets a json representation of the rule
         *
         * \return json representation of the rule as string
         */
        std::string getJsonRule (void) const;
        /// save rule to persistence storage
        void save (const std::string &path) const;
        /// remove rule from persistence storage
        int remove (const std::string &path);
};

class RuleTest : public Rule {
    public:
        std::string whoami () const { return "test"; };
        std::string evaluate (const VectorStrings &metrics) { return "eval"; };
        RuleTest (const std::string name, const VectorStrings metrics, const VectorStrings assets,
                const VectorStrings categories, const ResultsMap results) : Rule (name, metrics, assets, categories,
                results) { };
        RuleTest (const cxxtools::SerializationInfo &si) : Rule (si) { };
};

class RuleMatcher {
public:
    virtual bool operator ()(const Rule &rule) = 0;
protected:
    virtual ~RuleMatcher () = default;
};

class RuleNameMatcher : public RuleMatcher {
public:
    RuleNameMatcher (const std::string &name);
    bool operator ()(const Rule &rule) override;
private:
    std::string name_;
};

class RuleAssetMatcher : public RuleMatcher {
public:
    RuleAssetMatcher (const std::string &asset);
    bool operator ()(const Rule &rule) override;
private:
    std::string asset_;
};

/*
 * \brief Deserialzation of outcome
 */
/// serialization of outcome
void operator>>= (const cxxtools::SerializationInfo& si, Rule::Outcome& outcome);

/// serialization of values (global variables)
void operator>>= (const cxxtools::SerializationInfo& si, Rule::VariableMap &values);

/// serialization of results
void operator>>= (const cxxtools::SerializationInfo& si, Rule::ResultsMap &outcomes);

#endif // __rule_guard__
