/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include <sys/time.h>
#include <time.h>
#include <jansson.h>

/* $CompileFlags: */
/* $LinkerFlags: -ljansson */

class ArchiveMode : public SimpleChannelModeHandler
{

 public:
	ArchiveMode(Module* Creator) : SimpleChannelModeHandler(Creator, "archive", 'W')
	{
	}

	ModeAction OnSet(User* source, Channel* channel, std::string& parameter)
	{
		return MODEACTION_ALLOW;
	}
};

class ModuleChanArchive : public Module
{
	ArchiveMode archive_mode;
        std::string archive_filename;

 private:
        struct timeval GetCurrentTime()
        {
                struct timeval current_time;
                gettimeofday(&current_time, NULL);

                return current_time;
        }

 public:
	ModuleChanArchive() : archive_mode(this)
	{
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("chanarchive");
                archive_filename = tag->getString("filename", "/tmp/irc.log");
	}

        void log_json(Channel *c, const std::string &command, const std::string &text, const std::string &raw_irc)
        {
                FILE *archive;
                archive = fopen(archive_filename.c_str(), "a+");
                struct timeval current_time = GetCurrentTime();
                struct tm *ptm = gmtime(&current_time.tv_sec);

                char timestamp[100];
                size_t buf_fill = strftime(timestamp, 100, "%Y-%m-%dT%H:%M:%S", ptm);
                snprintf(&timestamp[buf_fill], 100-buf_fill, ".%03dZ", current_time.tv_usec / 1000);

                json_t *json_root = json_object();
                json_object_set_new(json_root, "@timestamp", json_string(timestamp));
                json_object_set_new(json_root, "@version", json_string("1"));
                json_object_set_new(json_root, "logtype", json_string("irc"));
                json_object_set_new(json_root, "server", json_string(ServerInstance->Config->ServerName.c_str()));
                json_object_set_new(json_root, "channel", json_string(c->name.c_str()));
                json_object_set_new(json_root, "command", json_string(command.c_str()));
                json_object_set_new(json_root, "text", json_string(text.c_str()));
                json_object_set_new(json_root, "raw", json_string(raw_irc.c_str()));

                fprintf(archive, "%s\n", json_dumps(json_root, JSON_PRESERVE_ORDER));
                fclose(archive);
        }

	void OnUserMessage(User* user, void* dest, int target_type, const std::string &text, char status, const CUList&, MessageType msgtype) CXX11_OVERRIDE
	{
                if ((target_type != TYPE_CHANNEL) || (status != 0)) {
                    return;
                }

		Channel* c = (Channel*)dest;
                if (!c->IsModeSet(archive_mode)) {
                    return;
                }

                std::string msg_string = "";
                switch (msgtype) {
                    case MSG_PRIVMSG:
                        msg_string = "PRIVMSG";
                        break;
                    case MSG_NOTICE:
                        msg_string = "NOTICE";
                        break;
                    default:
                        return;
                }
		const std::string raw_irc = ":" + user->GetFullHost() + " " + msg_string + " " + c->name + " :" + text;

                log_json(c, msg_string, text, raw_irc);
	}

        void OnPostTopicChange(User *user, Channel *c, const std::string &topic)
        {
                if (!c->IsModeSet(archive_mode)) {
                    return;
                }

                const std::string command = "TOPIC";
		const std::string raw_irc = ":" + user->GetFullHost() + " " + command.c_str() + " " + c->name + " :" + topic;

                log_json(c, command, topic, raw_irc);
        }

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Archive channel activity to specified logserver", VF_VENDOR);
	}
};

MODULE_INIT(ModuleChanArchive)
