/*  =========================================================================
    alert_list - Actor to serve REST API requests about alerts

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
    =========================================================================
*/

#ifndef ALERT_LIST_H_INCLUDED
#define ALERT_LIST_H_INCLUDED

#include "alert.h"

//  @interface
class AlertList {
    public:
        AlertList ()
        {
            m_Mailbox_client = mlm_client_new ();
            m_Stream_client = mlm_client_new ();
        }
        void alert_list_actor (zsock_t *pipe, void *args);
        void alert_list_test (bool verbose);
        ~AlertList ()
        {
            mlm_client_destroy (&m_Mailbox_client);
            mlm_client_destroy (&m_Stream_client);
        }
    private:
        void filter_alerts_for_publishing
            (std::vector<Alert> alerts,
             std::function<bool(Alert alert)> filter,
             zmsg_t *reply);
        void alert_cache_clean ();
        void process_mailbox (zmsg_t *msg);
        void process_stream (zmsg_t *msg);
        std::string handle_rule (std::string rule);
        void handle_alert (fty_proto_t *msg, std::string subject);

        mlm_client_t *m_Mailbox_client;
        mlm_client_t *m_Stream_client;
        std::map<std::string, Alert> m_Alert_cache;
        std::map<std::string, std::vector<std::shared_ptr<Alert>>> m_Asset_alerts;
        std::map<std::string, uint64_t> m_Last_send;
};
//  @end

#endif
