#ifndef __RULE_FACTORY_GUARD__
#define __RULE_FACTORY_GUARD__

#include <memory>
#include <cxxtools/serializationinfo.h>
#include <cxxtools/jsondeserializer.h>
#include <sstream>
#include <fty_log.h>

#include "rule.h"
#include "extended_rules.h"

class RuleFactory {
    public:
        /// create Rule object from cxxtools::SerializationInfo
        static std::unique_ptr<Rule> createFromSerializationInfo (const cxxtools::SerializationInfo &si) {
            auto elem_content = si.getMember (0);
            if (elem_content.category () != cxxtools::SerializationInfo::Object) {
                log_error ("Root of json must be type object.");
                throw std::runtime_error ("Root of json must be type object.");
            }
            if (elem_content.name () == "simple") {
                return std::unique_ptr<Rule>(new SingleRule (si));
            } else if (elem_content.name () == "pattern") {
                return std::unique_ptr<Rule>(new PatternRule (si));
            } else if (elem_content.name () == "threshold") {
                return std::unique_ptr<Rule>(new ThresholdRule (si));
            } else if (elem_content.name () == "flexible") {
                return std::unique_ptr<Rule>(new FlexibleRule (si));
            } else {
                std::ostringstream oss;
                si.dump (oss);
                log_error ("Unrecognized rule '%s'", oss.str ().c_str ());
                throw std::runtime_error ("Unrecognized rule '" + oss.str () + "'");
            }
        }
        /// create Rule object from JSON format
        static std::unique_ptr<Rule> createFromJson (std::string &json) {
            std::istringstream iss (json);
            cxxtools::JsonDeserializer jd (iss);
            if (jd.si () != nullptr) {
                return createFromSerializationInfo (*jd.si ());
            } else {
                throw std::runtime_error ("JSON deserializer has null SerializationInfo for input: " + json);
            }
        }
};

#endif // __rule_factory_guard__
