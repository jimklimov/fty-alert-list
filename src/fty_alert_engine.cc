/*
Copyright (C) 2014 - 2019 Eaton

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

/*! \file fty_alert_engine.cc
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Starts the alert agent
 */
#define DEFAULT_LOG_CONFIG "/etc/fty/ftylog.cfg"
#define DEFAULT_ENDPOINT "ipc://@/malamute"
#define DEFAULT_TTLCLEANUP_INTERVAL 60

#include "fty_common_agents.h"
#include "fty_alert_engine_classes.h"

static int
s_ttl_cleanup_timer (zloop_t *loop, int timer_id, void *output) {
    zstr_send(output, "TTLCLEANUP");
    return 0;
}

int main (int argc, char *argv [])
{
    bool verbose = false;
    int argn;
    ManageFtyLog::setInstanceFtylog (AGENT_FTY_ALERT_LIST, DEFAULT_LOG_CONFIG);
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-alert-list [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            return 0;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v")) {
            verbose = true;
            ManageFtyLog::getInstanceFtylog()->setVeboseMode();
        }
        else
        if (streq (argv [argn], "--config")
        || streq (argv [argn], "-c")) {
            // TODO: process config file
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //  Insert main code here
    if (verbose)
        log_info ("fty_alert_list - agent for alert REST API interface");

    AlertList alert_list_server;
    zactor_t *alert_list_actor = zactor_new (std::mem_fun (&AlertList::alert_list_actor), AGENT_FTY_ALERT_LIST);
    zstr_sendx (alert_list_actor, "CONNECT", DEFAULT_ENDPOINT, AGENT_FTY_ALERT_LIST, NULL);
    zstr_sendx (alert_list_actor, "CONSUMER", FTY_PROTO_STREAM_ALERTS_SYS, ".*", NULL);
    zstr_sendx (alert_list_actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (alert_list_actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS, NULL);

    zloop_t *ttlcleanup = zloop_new ();
    zloop_timer (ttlcleanup, 60 * 1000, 0, s_ttl_cleanup_timer, alert_list_actor);
    zloop_start (ttlcleanup);

    zloop_destroy (&ttlcleanup);
    zactor_destroy (&alert_list_actor);
    return 0;
}
