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

/*! \file purealert.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief General representation of alert
 */
#ifndef SRC_PUREALERT_H
#define SRC_PUREALERT_H

#include <string>
#include <vector>
#include <czmq.h>

#define ALERT_UNKNOWN  0
#define ALERT_START    1
#define ALERT_ACK1     2
#define ALERT_ACK2     3
#define ALERT_ACK3     4
#define ALERT_ACK4     5
#define ALERT_RESOLVED 6

const char* get_status_string(int status)
{
    switch (status) {
        case ALERT_START:
            return "ACTIVE";
        case ALERT_ACK1:
            return "ACK-WIP";
        case ALERT_ACK2:
            return "ACK-PAUSE";
        case ALERT_ACK3:
            return "ACK-IGNORE";
        case ALERT_ACK4:
            return "ACK-SILENCE";
        case ALERT_RESOLVED:
            return "RESOLVED";
    }
    return "UNKNOWN";
}


struct PureAlert{
    int _status; // on Off ack
    int64_t _timestamp;
    std::string _description;
    std::string _element;
    std::string _severity;
    std::vector <std::string> _actions;

    PureAlert(int s, int64_t tm, const std::string &descr, const std::string &element_name)
    {
        _status = s;
        _timestamp = tm;
        _description = descr;
        _element = element_name;
    };
    
    PureAlert(int s, int64_t tm, const std::string &descr, const std::string &element_name, const std::string &severity, const std::vector<std::string> &actions)
    {
        _status = s;
        _timestamp = tm;
        _description = descr;
        _element = element_name;
        _severity = severity;
        _actions = actions;
    };

    PureAlert()
    {
    };
};

void printPureAlert(const PureAlert &pureAlert){
    zsys_info ("status = %d", pureAlert._status);
    zsys_info ("timestamp = %d", pureAlert._timestamp);
    zsys_info ("description = %s", pureAlert._description.c_str());
    zsys_info ("element = %s", pureAlert._element.c_str());
    zsys_info ("severity = %s", pureAlert._severity.c_str());
};

#endif // SRC_PURE_ALERT_H_
