/*  =========================================================================
    fty_alert_list - description

    Copyright (C) 2014 - 2017 Eaton                                        
                                                                           
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
    fty_alert_list -
@discuss
@end
*/

#include "fty_alert_list_classes.h"

static int
s_ttl_cleanup_timer (zloop_t *loop, int timer_id, void *output)
{
    zstr_send (output, "TTLCLEANUP");
    return 0;
}

int main (int argc, char *argv [])
{
    bool verbose = false;
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help") ||
            streq (argv [argn], "-h")) {
            puts ("fty-alert-list [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            return 0;
        }
        else if (streq (argv [argn], "--verbose") ||
                 streq (argv [argn], "-v")) {
            verbose = true;
        } 
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //  Insert main code here
    if (verbose)
        zsys_info ("fty-alert-list - Agent providing information about active alerts"); // TODO: rewite alerts_list_server to accept VERBOSE

    zsys_info ("fty-alert-list starting");
    const char *endpoint = "ipc://@/malamute";
    zactor_t *alert_list_server = zactor_new (fty_alert_list_server, (void *) endpoint);

    zloop_t *ttlcleanup = zloop_new ();
    zloop_timer (ttlcleanup, 60*1000, 0, s_ttl_cleanup_timer, alert_list_server);
    zloop_start (ttlcleanup);
    
    // 
    while (!zsys_interrupted) {
        sleep (1000);
    }
    
    zloop_destroy (&ttlcleanup);
    zactor_destroy (&alert_list_server);
    return EXIT_SUCCESS;
}
