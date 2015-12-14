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

/*! \file bios-agent-alert-generator.cc
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Starts the alert agent
 */

#include "../include/alert_agent.h"

// path to the directory, where rules are stored. Attention: without last slash!
#define PATH "/var/lib/bios/alert_agent"

// agents name
#define AGENT_NAME "alert-agent"

// malamute endpoint
#define ENDPOINT "ipc://@/malamute"


int main (int argc, char** argv)
{
    if (argc > 3) {
        zsys_error ("Usage: %s [malamute-endpiont] [config-path]", argv[0]);
        exit (EXIT_FAILURE);
    }

    const char* path = ( argc == 3 ) ? PATH : argv[2];
    const char* end_point = ( argc > 1 )? ENDPOINT : argv[1];

    zactor_t *ag_server = zactor_new (bios_alert_generator_server, (void*) AGENT_NAME);
    zstr_sendx (ag_server, "CONNECT", end_point, NULL);
    zstr_sendx (ag_server, "PRODUCER", "ALERTS", NULL);
    zstr_sendx (ag_server, "CONFIG", path, NULL);

    //  Accept and print any message back from server
    //  copy from src/malamute.c under MPL license
    while (true) {
        char *message = zstr_recv (ag_server);
        if (message) {
            puts (message);
            free (message);
        }
        else {
            puts ("interrupted");
            break;
        }
    }

    // TODO save info to persistence before I die
    zactor_destroy (&ag_server);
    return 0;
}
