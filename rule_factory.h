#ifndef __RULE_FACTORY_GUARD__
#define __RULE_FACTORY_GUARD__

#include <stdexcept>
#include <memory>
#include <cxxtools/serializationinfo.h>
#include <cxxtools/jsondeserializer.h>
#include <sstream>
#include <fty_log.h>

#include "rule.h"
#include "extended_rules.h"

class RuleFactory {
    private:
        template <typename T>
        static std::unique_ptr<Rule> createRuleByName (const std::string &name, const T ruleSource) {
            if (name == "simple") {
                return std::unique_ptr<Rule>(new SingleRule (ruleSource));
            } else if (name == "pattern") {
                return std::unique_ptr<Rule>(new PatternRule (ruleSource));
            } else if (name == "threshold") {
                return std::unique_ptr<Rule>(new ThresholdRule (ruleSource));
            } else if (name == "flexible") {
                return std::unique_ptr<Rule>(new FlexibleRule (ruleSource));
            } else {
                throw std::runtime_error ("Unrecognized rule");
            }
        }
    public:
        /// create Rule object from cxxtools::SerializationInfo
        static std::unique_ptr<Rule> createFromSerializationInfo (const cxxtools::SerializationInfo &si) {
            const cxxtools::SerializationInfo &elem_content = si.getMember (0);
            if (elem_content.category () != cxxtools::SerializationInfo::Object) {
                log_error ("Root of json must be type object.");
                throw std::runtime_error ("Root of json must be type object.");
            }
            try {
                return createRuleByName (elem_content.name (), si);
            } catch (std::exception &e) {
                std::ostringstream oss;
                si.dump (oss);
                log_error ("Unrecognized rule '%s'", oss.str ().c_str ());
                throw std::runtime_error ("Unrecognized rule");
            }
        }
        /// create Rule object from JSON format
        static std::unique_ptr<Rule> createFromJson (const std::string &json) {
            std::istringstream iss (json);
            cxxtools::JsonDeserializer jd (iss);
            try {
                jd.deserialize ();
                return createFromSerializationInfo (*jd.current ());
                //createRuleByName (elem_content.name (), json);
            } catch (std::exception &e) {
                throw std::runtime_error ("JSON deserializer has null SerializationInfo for input: " + json);
            }
        }
};

#endif // __rule_factory_guard__
