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
    for (auto alert_pair : m_Alert_cache) {
        Alert alert = alert_pair.second;
        if ((alert.mtime () + alert.ttl () < now) && (alert.state() != "RESOLVED")) {
            alert.cleanup ();

            zmsg_t *fty_alert = alert.StaleToFtyProto ();
            int rv = mlm_client_send (m_Stream_client, alert.id().c_str (), &fty_alert);
            if (rv == -1) {
                log_error ("mlm_client_send (subject = '%s') failed", alert.id ().c_str ());
                zmsg_destroy (&fty_alert);
            }
        }
    }
}

void
AlertList::filter_alerts_for_publishing
    (std::vector<Alert> alerts,
     std::function<bool(Alert alert)> filter,
     zmsg_t *msg)
{
    /*std::vector<Alert> values;
    values.reserve (m_Alert_cache.size ());
    std::transform (m_Alert_cache.begin (), m_Alert_cache.end (), std::back_inserter (values),
            [](const std::pair<std::string, Alert> &p) { return p.second; });
    */
    std::vector<Alert> filtered_alerts;
    std::copy_if (
            alerts.begin(),
            alerts.end(),
            std::back_inserter (filtered_alerts),
            filter
            );

    for (auto alert : filtered_alerts) {
        int sep = alert.id().find ('@');
        std::string name = alert.id().substr (sep+1);
        std::shared_ptr<FullAsset> asset = FullAssetDatabase::getInstance ().getAsset (name);

        std::string ename = asset->getName ();
        std::string logical_asset_name, logical_asset_ename, normal_state, port;
        if (asset->getTypeString () == "device" && asset->getSubtypeString () == "sensorgpio") {
            logical_asset_name = asset->getAuxItem ("logical_asset");
            if (logical_asset_name.empty ())
                logical_asset_name = asset->getParentId ();
            std::shared_ptr<FullAsset> logical_asset = FullAssetDatabase::getInstance ().getAsset (logical_asset_name);
            logical_asset_ename = logical_asset->getName ();
            normal_state = asset->getExtItem ("normal_state");
            port = asset->getExtItem ("port");
        }

        zmsg_t *fty_alert = alert.toFtyProto (
                ename,
                logical_asset_name,
                logical_asset_ename,
                normal_state,
                port
                );
        zmsg_addmsg (msg, &fty_alert);
    }
}

std::string
AlertList::handle_rule (std::string rule)
{
    //TODO: deserialize rule
    std::unique_ptr<Rule> deserialized_rule =  RuleFactory::createFromJson (rule);
    std::string id = deserialized_rule->getName ();
    auto pos = m_Alert_cache.find (id);
    // new rule
    if (pos == m_Alert_cache.end ()) {
        for (auto asset : deserialized_rule->getAssets ()) {
            if (FullAssetDatabase::getInstance ().getAsset (asset) == nullptr) {
                // ask FTY_ASSET_AGENT for ASSET_DETAILS
                zuuid_t *uuid = zuuid_new ();
		zpoller_t *asset_helper = zpoller_new (mlm_client_msgpipe (m_Mailbox_client), NULL);
                mlm_client_sendtox (m_Mailbox_client, AGENT_FTY_ASSET, "ASSET_DETAIL", "GET",
                        zuuid_str_canonical (uuid), asset.c_str (), NULL);
                void *which = zpoller_wait (asset_helper, 5);
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
                        log_debug("received alert for %s, asked for it and was successful", asset.c_str ());
                        Alert rule_alert (id, deserialized_rule->getResults());
			            std::shared_ptr<Alert> rule_alert_ptr = std::make_shared<Alert> (rule_alert);
                        m_Alert_cache.insert (std::pair<std::string, Alert> (id, rule_alert));
                        m_Asset_alerts[asset].push_back (rule_alert_ptr);
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
    }
    // update of old rule
    else {
        //Alert rule_alert = *pos;
        pos->second.overwrite (deserialized_rule);
    }
    return id;
}

// This function receives alerts from FTY_PROTO_STREAM_ALERTS_SYS.
// In case of success, its result is publishing of new alert on FTY_PROTO_STREAM_ALERTS
void
AlertList::handle_alert (fty_proto_t *fty_new_alert, std::string subject)
{
    bool should_send = false;
    bool should_overwrite = false;

    // check if alert is in the cache
    std::string new_alert_id = std::string (fty_proto_rule (fty_new_alert)) + "@" + std::string (fty_proto_name (fty_new_alert));
    auto old_alert = m_Alert_cache.find (new_alert_id);
    if (old_alert == m_Alert_cache.end ()) {
         log_error ("Alert for non-existing rule %s", new_alert_id.c_str ());
    }
    else {
        const char* old_state = old_alert->second.state().c_str ();
        uint64_t old_last_sent = m_Last_send [new_alert_id];
        std::string old_outcome = old_alert->second.outcome ();
        std::string new_outcome = fty_proto_aux_string (fty_new_alert, "outcome", "OK");
        bool same_outcome = (old_outcome == new_outcome);

        old_alert->second.update (fty_new_alert);

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
            else if (streq (old_state, "ACTIVE")) {
                if (!same_outcome) {
                    should_overwrite = true;
                    should_send = true;
                }
                // if still active and same severity, publish only when we are at risk of timing out
                if ((zclock_mono ()/1000) >= (old_last_sent + fty_proto_ttl (fty_new_alert)/2)) {
                    should_send = true;
                }
                // always update the time - for the old alert directly in the cache
                old_alert->second.setMtime (fty_proto_time (fty_new_alert));
            }
            else { // some ACK-XXX state stored
                if (!same_outcome) {
                    should_send = true;
                }
            }
        }

        if (should_overwrite) {
            old_alert->second.overwrite (fty_new_alert);
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
AlertList::process_stream (zmsg_t *msg)
{
    if (!is_fty_proto (msg)) {
        log_error ("Message not fty_proto");
        return;
    }

    fty_proto_t *fty_msg = fty_proto_decode (&msg);
    if (!fty_msg) {
        log_error ("Failed to unpack fty_proto");
        return;
    }
    if (fty_proto_id (fty_msg) == FTY_PROTO_ALERT) {
        std::string subject = mlm_client_subject (m_Stream_client);
        handle_alert (fty_msg, subject);
    }
    else if (fty_proto_id (fty_msg) == FTY_PROTO_ASSET) {
        //handle_asset (alert_list_server, fty_msg);
        FullAsset asset(fty_msg);
        FullAssetDatabase::getInstance ().insertOrUpdateAsset (asset);
    }
    else {
        log_warning ("Message neither FTY_PROTO_ASSET nor FTY_PROTO_ALERT.");
    }
}

void
AlertList::process_mailbox (zmsg_t *msg)
{
    zmsg_t *reply = zmsg_new ();

    std::string subject = mlm_client_subject (m_Mailbox_client);
    std::string address = mlm_client_sender (m_Mailbox_client);
    std::string cmd = zmsg_popstr (msg);
    std::string correlation_id = zmsg_popstr (msg);
    if (cmd == "LISTALL" || cmd == "LIST") {
        if (subject != RFC_ALERTS_LIST_SUBJECT) {
            log_error ("Expected subject %s,  got %s", RFC_ALERTS_LIST_SUBJECT, subject.c_str ());
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "WRONG_SUBJECT");
        }

        const std::set<std::string> alert_filters =
            { "RESOLVED", "ACTIVE", "ACK-IGNORE", "ACK-PAUSE", "ACK-SILENCE", "ACK-WIP", "ALL-ACTIVE", "ALL" };
        std::string filter = zmsg_popstr (msg);

        if (alert_filters.find (filter) != alert_filters.end ()) {
            //std::vector<Alert> filtered_alerts;
            std::function<bool(Alert alert)> filter_fn;
            if (filter == "ALL") {
                // pass trivial lambda
                filter_fn = [filter](Alert alert) -> bool { return true; } ;
            }
            else if (filter == "ALL-ACTIVE") {
                // select everything except RESOLVED
                filter_fn = [filter](Alert alert) -> bool { return alert.state () != "RESOLVED"; } ;
            }
            else {
                // select by state
                filter_fn = [filter](Alert alert) -> bool { return alert.state () == filter; } ;
            }

            if (cmd == "LISTALL") {
                zmsg_addstr (reply, "LISTALL");
                zmsg_addstr (reply, correlation_id.c_str ());
                zmsg_addstr (reply, filter.c_str ());

                std::vector<Alert> values;
                values.reserve (m_Alert_cache.size ());
                std::transform (m_Alert_cache.begin (), m_Alert_cache.end (), std::back_inserter (values),
                        [](const std::pair<std::string, Alert> &p) { return p.second; });
                filter_alerts_for_publishing (values, filter_fn, reply);

/*                for (auto alert : filtered_alerts) {
                    int sep = alert.id().find ('@');
                    std::string name = alert.id().substr (sep+1);
                    std::shared_ptr<FullAsset> asset = FullAssetDatabase::getInstance ().getAsset (name);

                    std::string ename = asset->getName ();
                    std::string logical_asset_name, logical_asset_ename, normal_state, port;
                    if (asset->getTypeString () == "device" && asset->getSubtypeString () == "sensorgpio") {
                        logical_asset_name = asset->getAuxItem ("logical_asset");
                        if (logical_asset_name.empty ())
                            logical_asset_name = asset->getParentId ();
                        std::shared_ptr<FullAsset> logical_asset = FullAssetDatabase::getInstance ().getAsset (logical_asset_name);
                        logical_asset_ename = logical_asset->getName ();
                        normal_state = asset->getExtItem ("normal_state");
                        port = asset->getExtItem ("port");
                    }

                    zmsg_t *fty_alert = alert.toFtyProto (
                            ename,
                            logical_asset_name,
                            logical_asset_ename,
                            normal_state,
                            port
                            );
                    zmsg_addmsg (reply, &fty_alert);
                }*/
            }

            if (cmd == "LIST") {
                zmsg_addstr (reply, "LIST");
                zmsg_addstr (reply, correlation_id.c_str ());
                zmsg_addstr (reply, filter.c_str ());

                char *name = zmsg_popstr (msg);
                while (name) {
                    std::vector<std::shared_ptr<Alert>> asset_alerts = m_Asset_alerts [name];

                    std::vector<Alert> values;
                    values.reserve (asset_alerts.size ());
                    std::transform (asset_alerts.begin (), asset_alerts.end (), std::back_inserter (values),
                            [](const std::shared_ptr<Alert> p) { return *p; });
                    //filtered_alerts = filter_alerts (values, filter_fn);
                    filter_alerts_for_publishing (values, filter_fn, reply);
                    /*for (Alert alert : filtered_alerts) {
                        std::shared_ptr<FullAsset> asset = FullAssetDatabase::getInstance ().getAsset (name);
                        std::string ename = asset->getName ();
                        std::string logical_asset_name, logical_asset_ename, normal_state, port;
                        if (asset->getTypeString () == "device" && asset->getSubtypeString () == "sensorgpio") {
                            logical_asset_name = asset->getAuxItem ("logical_asset");
                            if (logical_asset_name.empty ())
                                logical_asset_name = asset->getParentId ();
                            std::shared_ptr<FullAsset> logical_asset = FullAssetDatabase::getInstance ().getAsset (logical_asset_name);
                            logical_asset_ename = logical_asset->getName ();
                            normal_state = asset->getExtItem ("normal_state");
                            port = asset->getExtItem ("port");
                        }

                        zmsg_t *fty_alert = alert.toFtyProto (
                                ename,
                                logical_asset_name,
                                logical_asset_ename,
                                normal_state,
                                port
                                );
                        zmsg_addmsg (reply, &fty_alert);
                    }*/
                    zstr_free (&name);
                    name = zmsg_popstr (msg);
                }
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
        std::string rule_id = handle_rule (rule);

        zmsg_addstr (reply, "ADD");
        zmsg_addstr (reply, correlation_id.c_str ());
        zmsg_addstr (reply, rule_id.c_str ());
    }
    else if (cmd == "CHANGESTATE") {
        if (subject != RFC_ALERTS_ACKNOWLEDGE_SUBJECT) {
            log_error ("Expected subject %s,  got %s", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, subject.c_str ());
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "WRONG_SUBJECT");
        }

        std::string alert_id = zmsg_popstr (msg);
        auto pos = m_Alert_cache.find (alert_id);
        if (pos == m_Alert_cache.end ()) {
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "NOT_FOUND");
        }
        std::string new_state = zmsg_popstr (msg);
        Alert alert = pos->second;
        int rv = alert.switchState (new_state);

        if (rv) {
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, "BAD_STATE");
        }
        else {
            zmsg_addstr (reply, "CHANGESTATE");
            zmsg_addstr (reply, correlation_id.c_str ());
            zmsg_addstr (reply, alert.id().c_str ());
        }
    }
    else {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, correlation_id.c_str ());
        zmsg_addstr (reply, "BAD_COMMAND");
    }

    int rv = mlm_client_sendto (m_Mailbox_client, address.c_str (), subject.c_str (), NULL, 1000, &reply);
    if (rv == -1) {
        log_error ("mlm_client_sendto to '%s' failed", address.c_str ());
        zmsg_destroy (&reply);
    }
}

void
AlertList::alert_list_actor (zsock_t *pipe, void *args)
{
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (m_Mailbox_client), mlm_client_msgpipe (m_Stream_client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 1000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            std::string cmd = zmsg_popstr (msg);
            if (cmd == "$TERM") {
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
            else if (cmd == "CONSUMER") {
                std::string stream = zmsg_popstr (msg);
                std::string pattern = zmsg_popstr (msg);
                mlm_client_set_consumer (m_Stream_client, stream.c_str (), pattern.c_str ());
            }
            else if (cmd == "TTLCLEANUP") {
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
            process_mailbox (msg);
            zmsg_destroy (&msg);
        } else if (which == mlm_client_msgpipe (m_Stream_client)) {
            zmsg_t *msg = mlm_client_recv (m_Stream_client);
            if (!msg) {
                break;
            }
            process_stream (msg);
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
