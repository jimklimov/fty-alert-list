#include <cxxtools/utf8codec.h>
#include <cxxtools/jsonserializer.h>
#include <fstream>
#include <algorithm>
#include <sstream>

#include "rule.h"

// 1, ..., 4 - # of utf8 octets
// -1 - error
static int8_t
utf8_octets (const std::string& s, std::string::size_type pos)
{
    assert (pos < s.length ());

    const char c = s[pos];
    if ((c & 0x80 ) == 0) {     // lead bit is zero, must be a single ascii
        return 1;
    }
    else
    if ((c & 0xE0 ) == 0xC0 ) { // 110x xxxx (2 octets)
        return 2;
    }
    else
    if ((c & 0xF0 ) == 0xE0 ) { // 1110 xxxx (3 octets)
        return 3;
    }
    else
    if ((c & 0xF8 ) == 0xF0 ) { // 1111 0xxx (4 octets)
        return 4;
    }
    else {
        log_error ("Unrecognized utf8 lead byte '%x' in string '%s'", c, s.c_str ());
        return -1;
    }
}

// 0 - same
// 1 - different
static int
utf8_compare_octets (const std::string& s1, std::string::size_type s1_pos, const std::string& s2, std::string::size_type s2_pos, uint8_t count)
{
    assert (count >= 1 && count <= 4);
    assert (s1_pos + count <= s1.length ());
    assert (s2_pos + count <= s2.length ());

    for (int i = 0; i < count; i++) {
        const char c1 = s1[s1_pos + i];
        const char c2 = s2[s2_pos + i];

        if ((count == 1 && tolower (c1) != tolower (c2)) ||
            (count > 1  && c1 != c2))
            return 1;
    }
    return 0;
}

int
utf8eq (const std::string& s1, const std::string& s2)
{
    if (s1.length () != s2.length ())
        return 0;

    std::string::size_type s1_pos = 0, s2_pos = 0;
    std::string::size_type length = s1.length ();


    while (s1_pos < length &&
           s2_pos < length)
    {
        uint8_t s1_octets = utf8_octets (s1, s1_pos);
        uint8_t s2_octets = utf8_octets (s2, s2_pos);

        if (s1_octets == -1 || s2_octets == -1)
            return -1;

        if (s1_octets != s2_octets)
            return 0;

        if (utf8_compare_octets (s1, s1_pos, s2, s2_pos, s1_octets) == 1)
            return 0;

        s1_pos = s1_pos + s1_octets;
        s2_pos = s2_pos + s1_octets;
    }
    return 1;
}

void
si_getValueUtf8 (const cxxtools::SerializationInfo& si, const std::string& membername_, std::string& result)
{
    std::basic_string <cxxtools::Char> cxxtools_Charname_;
    si.getMember (membername_).getValue (cxxtools_Charname_);
    result = cxxtools::Utf8Codec::encode (cxxtools_Charname_);
}


void Rule::setGlobalVariables (const VariableMap vars) {
    variables_.clear ();
    variables_.insert (vars.cbegin (), vars.cend ());
}

std::string Rule::getJsonRule (void) const {
    std::stringstream s;
    cxxtools::JsonSerializer js (s);
    js.beautify (true);
    cxxtools::SerializationInfo si;
    if (!saveToSerializedObject (si)) {
        throw std::runtime_error ("unable to serialize rule");
    }
    js.serialize (si).finish ();
    return s.str ();
}

void Rule::save (const std::string &path) const {
    std::string fullname = path + name_ + ".rule";
    log_debug ("trying to save file : '%s'", fullname.c_str ());
    std::ofstream ofs (fullname, std::ofstream::out);
    ofs.exceptions (~std::ofstream::goodbit);
    ofs << getJsonRule ();
    ofs.close ();
}

int Rule::remove (const std::string &path) {
    std::string fullname = path + name_ + ".rule";
    log_debug ("trying to remove file : '%s'", fullname.c_str ());
    return std::remove (fullname.c_str ());
}

RuleNameMatcher::RuleNameMatcher (const std::string &name) :
    name_ (name) {
}

bool RuleNameMatcher::operator ()(const Rule &rule) {
    return rule.getName () == name_;
}

RuleAssetMatcher::RuleAssetMatcher (const std::string &asset) :
    asset_ (asset) {
}

bool RuleAssetMatcher::operator ()(const Rule &rule) {
    return std::find (rule.getAssets ().begin (), rule.getAssets ().end (), asset_) != rule.getAssets ().end ();
}

/*
 * \brief Deserialization of outcome
 */
// TODO
void operator>>= (const cxxtools::SerializationInfo& si, Rule::Outcome& outcome)
{
    const cxxtools::SerializationInfo &actions = si.getMember ("action");
    outcome._actions.clear ();
    outcome._actions.reserve (actions.memberCount ());
    for ( const auto &a : actions) {
        std::string type, res;
        switch (a.category ()) {
        case cxxtools::SerializationInfo::Value:
            // old-style format ["EMAIL", "SMS"]
            outcome._actions.resize (outcome._actions.size () + 1);
            a >>= outcome._actions.back ();
            break;
        case cxxtools::SerializationInfo::Object:
            // [{"action": "EMAIL"}, {"action": "SMS"}]
            a.getMember ("action") >>= type;
            if (type == "EMAIL" || type == "SMS") {
                res = type;
            } else if (type == "GPO_INTERACTION") {
                std::string asset, mode;
                a.getMember ("asset") >>= asset;
                a.getMember ("mode") >>= mode;
                res = type + ":" + asset + ":" + mode;
            } else {
                log_warning ("Unknown action type: \"%s\"", type.c_str ());
                res = type;
            }
            outcome._actions.push_back (res);
            break;
        default:
            throw std::runtime_error ("Invalid format of action");
        }
    }
    si.getMember ("description") >>= outcome._description;
}
// TODO error handling mistakes can be hidden here
void operator>>= (const cxxtools::SerializationInfo& si, Rule::VariableMap &values)
{
    /*
       "values":[ {"low_critical"  : "30"},
                  {"low_warning"   : "40"},
                  {"high_warning"  : "50"},
                  {"high_critical" : "60"} ]
    */
    for ( const auto &oneElement : si ) { // iterate through the array
        auto variableName = oneElement.getMember (0).name ();
        std::string valueString;
        oneElement.getMember (0) >>= valueString;
        try {
            values.emplace (variableName, valueString);
        }
        catch (const std::exception &e ) {
            log_error ("Value '%s' is not double", valueString.c_str ());
            throw std::runtime_error ("Value should be double");
        }
    }
}
// TODO error handling mistakes can be hidden here
void operator>>= (const cxxtools::SerializationInfo& si, Rule::ResultsMap &outcomes)
{
    /*
        "results":[ {"low_critical"  : { "action" : [{ "action": "EMAIL"},{ "action": "SMS"}], "description" : "WOW low critical description" }},
                    {"low_warning"   : { "action" : [{ "action": "EMAIL"}], "description" : "wow LOW warning description"}},
                    {"high_warning"  : { "action" : [{ "action": "EMAIL"}], "description" : "wow high WARNING description" }},
                    {"high_critical" : { "action" : [{ "action": "EMAIL"}], "description" : "wow high critical DESCTIPRION" } } ]
    */
    for ( const auto &oneElement : si ) { // iterate through the array
        //we should ensure that only one member is present
        if (oneElement.memberCount ()!=1){
            throw std::runtime_error ("unexpected member count element in results");
        }
        auto outcomeName = oneElement.getMember (0).name ();
        Rule::Outcome outcome;
        oneElement.getMember (0) >>= outcome;
        if ( outcomeName == "low_critical" || outcomeName == "high_critical" ) {
            outcome._severity = "CRITICAL";
        }
        if ( outcomeName == "low_warning" || outcomeName == "high_warning" ) {
            outcome._severity = "WARNING";
        }
        if ( outcome._severity.empty () ) {
            throw std::runtime_error ("unsupported result");
        }
        outcomes.emplace (outcomeName, outcome);
    }
}
void loadMandatoryString (const cxxtools::SerializationInfo &si, std::string &name, std::string &target) {
    auto elem = si.getMember (name);
    if (elem.category () != cxxtools::SerializationInfo::Value) {
        log_error ("%s property must be value type.", name.c_str ());
        throw std::runtime_error ("%s property must be value type.", name.c_str ());
    }
    elem >>= target;
}
void loadOptionalString (const cxxtools::serializationinfo &si, std::string &name, std::string &target) {
    auto elem = si.findMember (name); // optional
    if (elem != nullptr) {
        if (elem.category () != cxxtools::SerializationInfo::Value) {
            log_error ("%s property must be value type.", name.c_str ());
            throw std::runtime_error ("%s property must be value type.", name.c_str ());
        } else {
            elem >>= target;
        }
    }
}
void loadMandatoryArray (const cxxtools::serializationinfo &si, std::string &name, Rule::VectorStrings &target) {
    auto elem = si.getMember (name); // mandatory
    if (elem.category () != cxxtools::SerializationInfo::Array) {
        log_error ("%s property must be an array type.", name.c_str ());
        throw std::runtime_error ("%s property must be an array type.", name.c_str ());
    }
    for (size_t i = 0; i < elem.memberCount (); ++i) {
        std::string val;
        elem.getMember (i).getValue (val);
        target.push_back (val);
    }
}
void loadMandatoryArrayOrValue (const cxxtools::serializationinfo &si, std::string &name, Rule::VectorStrings &target) {
    auto elem = si.getMember (name); // mandatory
    if (elem.category () == cxxtools::SerializationInfo::Value) {
        std::string val;
        elem >>= val;
        target.push_back (val);
    } else if (elem.category () == cxxtools::SerializationInfo::Array) {
        for (size_t i = 0; i < elem.memberCount (); ++i) {
            std::string val;
            elem.getMember (i).getValue (val);
            target.push_back (val);
        }
    } else {
        log_error ("%s property must be either an array type or value type.", name.c_str ());
        throw std::runtime_error ("%s property must be either an array type or value type.", name.c_str ());
    }
}

//TODO: FIXME:
void Rule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    try {
        auto elem_content = si.getMember (0);
        if (elem_content.category () != cxxtools::SerializationInfo::Object) {
            log_error ("Root of json must be an object with property 'single|pattern|threshold|flexible'.");
            throw std::runtime_error ("Root of json must be an object with property 'single|pattern|threshold|flexible'.");
        }
        loadMandatoryString (elem_content, "name", name_);
        loadOptionalstring (elem_content, "description", description_);
        loadOptionalString (elem_content, "class", class_);
        loadMandatoryArray (elem_content, "categories", categories_);
        loadMandatoryArrayOrValue (elem_content, "metrics", metrics_);
        auto elem_results = elem_content.getMember ("results"); // mandatory
        if ( elem_results.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("results property must be an array type.");
            throw std::runtime_error ("results property must be an array type.");
        }
        elem_results >>= results;
        loadOptionalString (elem_content, "source", source_);
        loadMandatoryArrayOrValue (elem_content, "assets", assets_);
        loadOptionalString (elem_content, "outcome_item_count", outcome_items_);
        auto elem_values = elem_content.findMember ("values"); // optional for general rule
        if (elem_values != nullptr) {
            if (elem_values.category () != cxxtools::SerializationInfo::Array ) {
                log_error ("values property must be an array type.");
                throw std::runtime_error ("values property must be an array type.");
            }
            elem_values >>= variables_;
        }
        loadOptionalString (elem_content, "values_unit", value_unit_);
        loadOptionalString (elem_content, "hierarchy", hierarchy_);
    } catch (std::exception &e) {
        std::ostringstream oss;
        si.dump (oss);
        log_error ("An error '%s' was caught while trying to read rule %s", e.what (), oss.str ());
    }
}
void Rule::saveToSerializedObject (const cxxtools::SerializationInfo &si) const {
    return 0;
}
