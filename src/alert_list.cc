/*  =========================================================================
    alert_list - Actor to serve REST API requests about alerts

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
    alert_list - Actor to serve REST API requests about alerts
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#define RFC_ALERTS_LIST_SUBJECT "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT  "rfc-alerts-acknowledge"

void
AlertList::alert_cache_clean ()
{
    uint64_t now = zclock_mono ()/1000;
    for (Alert alert : m_Alert_cache) {
        if ((alert.mtime () + alert.ttl () < now) && (alert.state() != RESOLVED)) {
            alert.cleanup ();

            fty_proto_t *fty_alert = alert.toFtyProto ();
            zmsg_t *encoded = fty_proto_encode (fty_alert);
            int rv = mlm_client_send (alert_list_server.m_Stream_client, alert.id().c_str (), &encoded);
            if (rv == -1) {
                log_error ("mlm_client_send (subject = '%s') failed", subject.c_str ());
                zmsg_destroy (&encoded);
            }
        }
    }
}

std::set<Alert>
AlertList::filter_alerts (std::function<bool(AlertState state)> filter)
{
    std::set<Alert> tmp;
    std::copy_if (
            m_Alerts_cache.begin(),
            m_Alerts_cache.end(),
            std::back_inserter (tmp),
            filter
            );
    return tmp;
}

AlertList::handle_rule (std::string rule)
{
    //TODO: deserialize rule
    Rule deserialized_rule;
    int pos = m_Alert_cache.find (deserialized_rule.id ());
    // new rule
    if (pos == std::npos) {
        int sep = m_Id.find ('@');
        std::string name = m_Id.substr (sep+1);
        if (m_Asset_cache.find (name) == std::npos) {
            // ask FTY_ASSET_AGENT for ASSET_DETAILS
            zuuid_t *uuid = zuuid_new ();
            mlm_client_sendtox (m_Mailbox_client, FTY_ASSET_AGENT_ADDRESS, "ASSET_DETAIL", "GET",
                    zuuid_str_canonical (uuid), name.c_str (), NULL);
            void *which = zpoller_wait (m_Mailbox_client, 5);
            if (which == NULL) {
                log_warning("no response from ASSET AGENT, ignoring this alert.");
            } else {
                zmsg_t *reply_msg = mlm_client_recv (m_Mailbox_client);
                char *rcv_uuid = zmsg_popstr (reply_msg);
                if (0 == strcmp (rcv_uuid, zuuid_str_canonical (uuid)) && fty_proto_is (reply_msg)) {
                    fty_proto_t *reply_proto_msg = fty_proto_decode (&reply_msg);
                    if (fty_proto_id (reply_proto_msg) != FTY_PROTO_ASSET) {
                        log_warning("unexpected response from ASSET AGENT, ignoring this alert.");
                    }
                    log_debug("received alert for %s, asked for it and was successful", name.c_str ());
                    Alert rule_alert (deserialized_rule.id(), deserialized_rule.results());
                    m_Alert_cache.insert (rule_alert);
                }
                else {
                    log_warning("received alert for unknown asset, ignoring.");
                    if (reply_msg) {
                        zmsg_destroy(&reply_msg);
                    }
                    // msg will be destroyed by caller
                }
                zstr_free(&rcv_uuid);
            }
            zuuid_destroy (&uuid);

        }
    }
    // update of old rule
    else {
        Alert rule_alert = m_Alert_cache[pos];
        rule_alert.overwrite (deserialized_rule);
    }
}

// This function receives alerts from FTY_PROTO_STREAM_ALERTS_SYS.
// In case of success, its result is publishing of new alert on FTY_PROTO_STREAM_ALERTS
// and if necessary, sending ACT to fty-alert-actions.
AlertList::handle_alert (fty_proto_t *fty_new_alert, std::string subject)
{
    bool should_send = false;
    bool should_overwrite = false;

    // check if alert is in the cache
    std::string new_alert_id = fty_proto_rule (fty_new_alert) + "@" + fty_proto_name (fty_new_alert);
    auto old_alert = m_Alert_cache.at (new_alert_id);
    if (old_alert == m_Alert_cache.end ()) {
         log_error ("Alert for non-existing rule %s", new_alert_id.c_str ())
    }
    else {
        const char* old_state = *old_alert.state().c_str ();
        unit64_t old_last_sent = m_Last_send [new_alert_id];
        std::string old_outcome = *old_alert.outcome ();
        std::string new_outcome = fty_proto_aux_string (fty_new_alert, "outcome", "OK");
        bool same_outcome = (old_outcome == new_outcome);

        *old_alert.update (fty_new_alert);

        // check if it has changed
        // RESOLVED comes from _ALERTS_SYS
        // * if stored !RESOLVED -> update stored time/state, publish original
        // * if stored RESOLVED -> don't update stored time, don't publish original
        if (streq (fty_proto_state (fty_new_alert), "RESOLVED")) {
            if (!streq (old_state, "RESOLVED")) {
                should_overwrite = true;
                should_send = true;
            }
        }

        //  ACTIVE comes form _ALERTS_SYS
        //  * if stored RESOLVED -> update stored time/state, publish modified, send ACT
        //  * if stored ACTIVE -> update time
        //      if severity change => publish else don't publish
        //  * if stored ACK-XXX -> Don't change state or time, don't publish

        if (streq (fty_proto_state (fty_new_alert), "ACTIVE")) {
            if (streq (old_state, "RESOLVED")) {
                should_overwrite = true;
                should_send = true;
            }
            else if (streq (fty_proto_state (fty_old_alert), "ACTIVE")) {
                if (!same_outcome) {
                    should_overwrite = true;
                    should_send = true;
                }
                // if still active and same severity, publish only when we are at risk of timing out
                if ((zclock_mono ()/1000) >= (old_last_sent + fty_proto_ttl (fty_old_alert)/2)) {
                    should_send = true;
                }
                // always update the time - for the old alert directly in the cache
                *oldAlert.setTime (fty_proto_time (fty_new_alert));
            }
            else { // some ACK-XXX state stored
                if (!same_outcome) {
                    should_send = true;
                }
            }
        }

        if (should_overwrite) {
            *old_alert.overwrite (fty_new_alert);
            fty_proto_aux_insert (fty_new_alert, "ctime", "%" PRIu64, fty_proto_time (fty_new_alert));
        }

        if (should_send) {
            fty_proto_t *alert_dup = fty_proto_dup (fty_new_alert);
            zmsg_t *encoded = fty_proto_encode (&alert_dup);
            assert (encoded);

            int rv = mlm_client_send (m_Stream_client, subject.c_str (), &encoded);
            if (rv == -1) {
                log_error ("mlm_client_send (subject = '%s') failed", subject.c_str ());
                zmsg_destroy (&encoded);
            }
            else {
                m_Last_send [new_alert_id] = zclock_mono ()/1000;
            }
        }
        fty_proto_destroy (&fty_new_alert);
    }
}


void
s_process_stream (AlertList alert_list_server, zmsg_t *msg)
{
    if (!is_fty_proto (*msg_p)) {
        log_error ("Message not fty_proto");
        return;
    }

    fty_proto_t *fty_msg = fty_proto_decode (msg_p);
    if (!fty_proto_msg) {
        log_error ("Failed to unpack fty_proto");
        return;
    }
    if (fty_proto_id (fty_msg) == FTY_PROTO_ALERT) {
        std::string subject = mlm_client_subject (alert_list_server.m_Stream_client);
        alert_list_server.handle_alert (ty_msg, subject);
    }
    else if (fty_proto_id (fty_msg) == FTY_PROTO_ASSET) {
        //handle_asset (alert_list_server, fty_msg);
        ExtendedAsset asset(fty_msg);
        alert_list_server.m_Asset_cache.insertOrUpdateAsset (asset);
    }
    else {
        log_warning ("Message neither FTY_PROTO_ASSET nor FTY_PROTO_ALERT.");
    }
}

void
s_process_mailbox (AlertList alert_list_server, zmsg_t *msg)
{
    zmsg_t *reply = zmsg_new ();

    std::string subject = mlm_client_subject (alert_list_server.m_Mailbox_client);
    std::string cmd = zmsg_popstr (msg);
    std::string correlation_id = zmsg_popstr (msg);
    if (cmd == "LIST") {
        if (subject != RFC_ALERTS_LIST_SUBJECT) {
            log_error ("Expected subject %s,  got %s", RFC_ALERTS_LIST_SUBJECT, subject.c_str ());
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "WRONG_SUBJECT");
        }

        const std::set<std::string> alert_filters =
            { "RESOLVED", "ACTIVE", "ACK-IGNORE", "ACK-PAUSE", "ACK-SILENCE", "ACK-WIP", "ALL-ACTIVE", "ALL" };
        std::string filter = zmsg_popstr (msg);

        if (filter.in (alert_filters) {
            std::set filtered_alerts;
            if (filter == "ALL") {
                // pass trivial lambda
                filtered_alerts = alert_list_server.filter_alerts
                    ( [filter](AlertState state) { return true; } );
            }
            else if (filter == "ALL-ACTIVE") {
                // select everything except RESOLVED
                filtered_alerts = alert_list_server.filter_alerts
                    ( [filter](AlertState state) { return state != RESOLVED; } );
            }
            else {
                // select by state
                filtered_alerts = alert_list_server.filter_alerts
                    ( [filter](AlertState state) {return AlertStateToString (state) == filter } );
            }

            zmsg_addstr (reply, "LIST");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, filter.c_str ());

            for (auto alert : filtered_alerts) {
                int sep = alert.id().find ('@');
                std::string name = alert.id().substr (sep+1);
                FullAsset asset = m_Asset_cache.getAsset (name);

                std::string ename = asset.getName ();
                std::string logical_assset_name(), logical_asset_ename(), normal_state(), port();
                if (asset.getTypeString () == "device" && asset.getSubtypeString () == "sensorgpio") {
                    logical_asset_name = asset.getAuxItem ("logical_asset");
                    if (logical_asset_name.empty ())
                        logical_asset_name = asset.getParentId ();
                    FullAsset logical_asset = m_Asset_cache.getAsset (logical_asset_name);
                    logical_asset_ename = logical_asset.getName ();
                    normal_state = asset.getExtItem ("normal_state");
                    port = asset.getExtItem ("port");
                }

                fty_proto_t *fty_alert = alert.toFtyProto (
                        ename,
                        logical_asset_name,
                        logical_asset_ename,
                        normal_state,
                        port
                        );
                zmsg_t *fty_alert_encoded = fty_proto_encode (fty_alert);
                zmsg_addmsg (reply, fty_alert_encoded);
            }
        }
        else {
            log_error ("Filter %s not allowed for alerts", filter.c_str ());
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "NOT_FOUND");
        }
    }
    else if (cmd == "ADD") {
        std::string rule = zmsg_popstr (msg);
        alert_list_server.handleRule (rule);

        zmsg_addstr (reply, "ADD");
        zmsg_addstr (reply, correlation_id.c_str ());
        zmsg_addstr (reply, deserialized_rule.id().c_str ());
    }
    else if (cmd == "CHANGESTATE") {
        if (subject != RFC_ALERTS_ACKNOWLEDGE_SUBJECT) {
            log_error ("Expected subject %s,  got %s", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, subject.c_str ());
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "WRONG_SUBJECT");
        }

        std::string alert_id = zmsg_popstr (msg);
        int pos = alert_list_server.m_Alert_cache.find (alert_id);
        if (pos == std::npos) {
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "NOT_FOUND");
        }
        std::string new_state = zmsg_popstr (msg);
        Alert alert = alert_list_server.m_Alert_cache[pos];
        int rv = alert.switchState (new_state);

        if (rv) {
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "BAD_STATE");
        }
        else {
            zmsg_addstr (reply, "CHANGESTATE");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, alert_id().c_str ());
        }
    }
    else {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, correlation_id.c_str ());
        zmsg_addstr (reply, "BAD_COMMAND");
    }

    int rv = mlm_client_sendto (alert_list_server.m_Mailbox_client, , ,,&reply);
    if (rv == -1) {
        log_error ("mlm_client_sendto to '%s' failed", );
        zmsg_destroy (&actions_msg);
    }
}

void
AlertList::fty_alert_list_server_actor (zsock_t *pipe, void *args)
{
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (m_Mailbox_client), mlm_client_msgpipe (m_Stream_client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 1000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            std::string cmd = zmsg_popstr (msg);
            if (cmd == "$TERM") {
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else if (cmd == "CONNECT") {
                std::string endpoint = zmsg_popstr (msg);
                std::string name = zmsg_popstr (msg);
                std::string stream_name = name + "-stream";
                mlm_client_connect (m_Mailbox_client, endpoint.c_str (), 1000, name.c_str ());
                mlm_client_connect (m_Stream_client, endpoint.c_str (), 1000, stream_name.c_str ());
            }
            else if (cmd == "PRODUCER") {
                std::string stream = zmsg_popstr (msg);
                mlm_client_set_producer (m_Stream_client, stream.c_str ());
            }
            else if (streq (cmd, "CONSUMER")) {
                std::string stream = zmsg_popstr (msg);
                std::string pattern = zmsg_popstr (msg);
                mlm_client_set_consumer (m_Stream_client, stream.c_str (), pattern.c_str ());
            }
            else if (streq (cmd, "TTLCLEANUP")) {
                alert_cache_clean ();
            }
            else {
                log_warning ("Unknown command '%s' on pipe", cmd.c_str ());
            }
            zmsg_destroy (&msg);
        } else if (which == mlm_client_msgpipe (m_Mailbox_client)) {
            zmsg_t *msg = mlm_client_recv (m_Mailbox_client);
            if (!msg) {
                break;
            }
            s_process_mailbox (this, msg);
            zmsg_destroy (&msg);
        } else if (which == mlm_client_msgpipe (m_Stream_client)) {
            zmsg_t *msg = mlm_client_recv (m_Stream_client);
            if (!msg) {
                break;
            }
            s_process_stream (this, msg);
            zmsg_destroy (&msg);
        } else {
             log_warning ("Unexpected message");
        }
    }
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
alert_list_test (bool verbose)
{
    printf (" * fty_alert_list_server: ");

    //  @selftest
    //  Simple create/destroy test
    AlertList alert_list_server();

    // send asset - DC
    // add rule
    // send ACTIVE alert
    // LIST ALL
    // send RESOLVED alert
    // LIST ALL
    //  @end
    printf ("OK\n");
}
