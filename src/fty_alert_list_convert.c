/*  =========================================================================
    fty_alert_list_convert - Converts bios_proto state file to fty_proto state.

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
    fty_alert_list_convert - Converts bios_proto state file to fty_proto state.
@discuss
@end
*/

#include "fty_alert_list_classes.h"

int
convert_file (const char *file_name, char *old_path, char *new_path)
{
    assert (file_name);
    assert (old_path);
    assert (new_path);

    zsys_debug ("I am converting state_file %s/%s and saving it to %s/%s.\n", old_path, file_name, new_path, file_name);

    zfile_t *file = zfile_new (old_path, file_name);
    if (!file) {
        zsys_error ("zfile_new (path = '%s', file = '%s') failed.", old_path, file_name);
        return -1;
    }
    if (!zfile_is_regular (file)) {
        zsys_error ("zfile_is_regular () == false");
        zfile_close (file);
        zfile_destroy (&file);
        return -1;
    }
    if (zfile_input (file) == -1) {
        zfile_close (file);
        zfile_destroy (&file);
        zsys_error ("zfile_input () failed; filename = '%s'", zfile_filename (file, NULL));
        return -1;
    }

    off_t cursize = zfile_cursize (file);
    if (cursize == 0) {
        zsys_debug ("state file '%s' is empty", zfile_filename (file, NULL));
        zfile_close (file);
        zfile_destroy (&file);
        return 0;
    }

    zchunk_t *chunk = zchunk_read (zfile_handle (file), cursize);
    assert (chunk);
    zframe_t *frame = zframe_new (zchunk_data (chunk), zchunk_size (chunk));
    assert (frame);

    zchunk_destroy (&chunk);

    zfile_close (file);
    zfile_destroy (&file);

    uint64_t offset = 0;
    zsys_debug ("zfile_cursize == %d", cursize);

    //cunk for new state file
    zchunk_t *nchunk = zchunk_new (NULL, 0);
    assert (nchunk);

    while (offset < cursize) {
        byte *prefix = zframe_data (frame) + offset;
        byte *data = zframe_data (frame) + offset + sizeof (uint64_t);
        offset += (uint64_t) *prefix +  sizeof (uint64_t);
        zsys_debug ("prefix == %d; offset = %d ", (uint64_t ) *prefix, offset);

        zmsg_t *zmessage;
#if CZMQ_VERSION_MAJOR == 3
        zmessage = zmsg_decode (data, (size_t) *prefix);
#else
        {
            zframe_t *fr = zframe_new (data, (size_t) *prefix);
            zmessage = zmsg_decode (fr);
            zframe_destroy (&fr);
        }
#endif
        assert (zmessage);

        bios_proto_t *balert = bios_proto_decode (&zmessage);
        assert (balert);
        fty_proto_t *falert = fty_proto_new (2);
        assert (falert);

        fty_proto_set_time (falert, bios_proto_time (balert));
        fty_proto_set_ttl (falert, (uint32_t) bios_proto_aux_number (balert, "ttl", 900));
        fty_proto_set_rule (falert, "%s", bios_proto_rule (balert));
        fty_proto_set_name (falert, "%s", bios_proto_element_src (balert));
        fty_proto_set_state (falert, "%s", bios_proto_state (balert));
        fty_proto_set_severity (falert, "%s", bios_proto_severity (balert));
        fty_proto_set_description (falert, "%s", bios_proto_description (balert));
        fty_proto_set_action (falert, "%s", bios_proto_action (balert));

        bios_proto_destroy (&balert);

        // --- save the data----
        zmsg_t *zmsg = fty_proto_encode (&falert);
        assert (zmsg);

#if CZMQ_VERSION_MAJOR == 3
        byte *buffer = NULL;
        uint64_t size = zmsg_encode (zmsg, &buffer);
        zmsg_destroy (&zmsg);

        assert (buffer);
        assert (size > 0);
        zframe_t *nframe = zframe_new (buffer, size);
        free (buffer); buffer = NULL;
#else
        zframe_t *nframe = zmsg_encode (zmsg);
        uint64_t size = zframe_size (nframe);
        zmsg_destroy (&zmsg);
#endif
        assert (nframe);

        // prefix
        zchunk_extend (nchunk, (const void *) &size, sizeof (uint64_t));
        // data
        zchunk_extend (nchunk, (const void *) zframe_data (nframe), size);

        zframe_destroy (&nframe);
        fty_proto_destroy (&falert);
    }

    zfile_t *nfile = zfile_new (new_path, file_name);
    if (!nfile) {
        zsys_error ("zfile_new (path = '%s', file = '%s') failed.", new_path, file_name);
        return -1;
    }

    int rv = zfile_output (nfile);
    assert (rv != -1);

    if (zchunk_write (nchunk, zfile_handle (nfile)) == -1) {
        zsys_error ("zchunk_write () failed.");
    }

    zchunk_destroy (&nchunk);
    zfile_close (nfile);
    zfile_destroy (&nfile);

    return 0;
}


int main (int argc, char *argv [])
{
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-alert-list-convert [file_name] [old_path] [new_path]");
            puts ("Converts bios_proto state file to fty_proto state file.");
            puts ("  --help / -h            this information");
            return 0;
        }
    }

    int rv = convert_file  (argv [1], argv [2], argv [3]);
    assert (rv == 0);

    return 0;
}
