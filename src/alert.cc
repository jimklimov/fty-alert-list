/*  =========================================================================
    alert - Alert representation

    Copyright (C) 2014 - 2018 Eaton

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
    =========================================================================
*/

/*
@header
    alert - Alert representation
@discuss
@end
*/

#include "alert.h"
#include "fty_alert_engine_classes.h"

void
Alert::update (fty_proto_t *msg)
{
    std::string outcome = fty_proto_aux_string (msg, "outcome", "OK");
    m_Outcome = outcome;
    if (m_Ctime == 0)
        m_Ctime = fty_proto_time (msg);
    m_Ttl = fty_proto_ttl (msg);
    m_Severity = m_Results[outcome]["severity"][0];
    m_Description = m_Results[outcome]["description"][0];
    m_Actions = m_Results[outcome]["actions"];
}

void
Alert::overwrite (fty_proto_t *msg)
{
    if (!isAckState (m_State))
        m_State = StringToAlertState (fty_proto_state (msg));
    m_Ctime = fty_proto_time (msg);
    m_Mtime = fty_proto_time (msg);
}

void
Alert::overwrite (Rule rule)
{
    m_Id = rule.id ();
    m_Results = rule.results ();
    m_State = RESOLVED;
    m_Outcome = "OK";
    m_Ctime = 0;
    m_Mtime = 0;
    m_Ttl = std::numeric_limits<uint64_t>::max ();
    m_Severity.clear ();
    m_Description.clear ();
    m_Actions.clear ();
}

void
Alert::cleanup ()
{
    uint64_t now = zclock_mono ()/1000;
    m_State = RESOLVED;
    m_Severity = "OK";
    m_Ctime = now;
    m_Mtime = now;
}

int
Alert::switch_state (std::string state_str) {
    if (state_str == "RESOLVED") {
        // allow this transition always
        m_State = RESOLVED;
    }
    else if (state_str == "ACK-IGNORE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKIGNORE;
    }
    else if (state_str == "ACK-PAUSE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKPAUSE;
    }
    else if (state_str == "ACK-SILENCE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKSILENCE;
    }
    else if (state_str == "ACK-WIP") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKWIP;
    }
    else if (state_str == "ACTIVE") {
        if (isAckState (m_State))
            return -1;
        else
            m_State = ACTIVE;
    }
    return 0;
}

zmsg_t *
Alert::toFtyProto()
{
    zhash_t *aux = zhash_new ();
    zhash_insert (aux, "ctime", (void *) m_Ctime);

    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    for (auto action : m_Actions) {
        zlist_append (actions, (void *) action.c_str ());
    }

    int sep = m_Id.find ('@');
    std::string rule = m_Id.substr (0, sep-1);
    std::string name = m_Id.substr (sep+1);

    zmsg_t *tmp = fty_proto_encode_alert (
            aux,
            m_Mtime,
            m_Ttl,
            rule.c_str (),
            name.c_str (),
            AlertStateToString (m_State).c_str (),
            m_Severity.c_str (),
            m_Description.c_str (),
            actions
            );

    return tmp;
}


//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
alert_test (bool verbose)
{
    printf (" * alert: ");

    std::vector<std::string> tmp1;
    std::map<std::string, std::vector<std::string>> tmp2;
    std::map<std::string, std::map<std::string,std::vector<std::string>>> tmp3;
    tmp2.insert (std::pair<std::string, std::vector<std::string>> ("foo", tmp1));
    tmp3.insert (std::pair<std::string, std::map<std::string, std::vector<std::string>>> ("bar", tmp2));
    //  @selftest
    //  Simple create/destroy test
    Alert alert ("id", tmp3);
    //  @end
    printf ("OK\n");
}
