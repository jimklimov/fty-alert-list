/*
Copyright (C) 2014 - 2015 Eaton

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/*! \file alertconfiguration.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of alert configuration
 */

#ifndef SRC_ALERTCONFIGURATION_H
#define SRC_ALERTCONFIGURATION_H

#include <istream>
#include <string>
#include <set>
#include <vector>
#include <memory>

#include "rule.h"
#include "purealert.h"

// It tries to parse and read JSON rules
// \return 1 if rule has errors in json
//         2 if lua function has errors
//         0 if everything is ok
int readRule (std::istream &f, RulePtr &rule);


// Alert configuration is a class that manages rules and evaruted alerts
//
// ASSUMPTIONS:
//  1. Rules are stored in files. One rule = one file
//  2. File name is a rule name
//  3. Files should have extention ".rule"
//  4. Directory to the files is configurable. Cannot be changed without recompilation
//  5. If rule has at least one mistake or broke any other rule, it is ignored
//  6. Rule name is unique
//
class AlertConfiguration{
public:

    typedef typename std::vector <std::pair<RulePtr, std::vector<PureAlert> > > A;
    typedef typename A::value_type value_type;
    typedef typename A::iterator iterator;

    /*
     * \brief Creates an empty rule-alert configuration with empty path
     *
     */
    AlertConfiguration ()
        : _path{}
    {};

    /*
     * \brief Creates an empty rule-alert configuration
     *
     * \param[in] @path - a directory where rules are stored
     */
    AlertConfiguration (const std::string &path)
        : _path (path)
    {};

    /*
     * \brief Reads the configuration from persistence
     *
     * Set of topics is empty if there are no rules or there are some errors
     *
     * \return a set of topics to be consumed
     */
    std::set <std::string> readConfiguration (void);

    // XXX: this exposes a lot of internal stuff - we need iterator as a class, not just typedef
    iterator begin() { return _alerts.begin(); }
    iterator end() { return _alerts.end(); }

    void setPath (const char* path) {
        _path = path;
    }

    // alertsToSend must be send in the order from first element to last element!!!
    int addRule (
        std::istream &newRuleString,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        iterator &it);

    // alertsToSend must be send in the order from first element to last element!!!
    int updateRule (
        std::istream &newRuleString,
        const std::string &rule_name,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        iterator &it);

    int updateAlert (const RulePtr &rule, const PureAlert &pureAlert, PureAlert &alert_to_send);

    bool haveRule (const RulePtr &rule) const {
        return haveRule (rule->name ());
    };

    bool haveRule (const std::string &rule_name) const {
        for ( const auto &i: _alerts ) {
            const auto &oneKnownRule = i.first;
            if ( oneKnownRule->hasSameNameAs(rule_name) )
                return true;
        }
        return false;
    };

    int
        updateAlertState (
                const char *rule_name,
                const char *element_name,
                const char *new_state,
                PureAlert &pureAlert);

    std::string getPersistencePath(void) {
        return _path + '/';
    }

private:
    // TODO it is bad implementation, any improvements are welcome
    A _alerts;

    // directory, where rules are stored
    std::string _path;
};

#endif // SRC_ALERTCONFIGURATION_H
