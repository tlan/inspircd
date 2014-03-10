/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2011 Pierre Carrier <pierre@spotify.com>
 *   Copyright (C) 2009-2010 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2009 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2008 Pippijn van Steenhoven <pip88nl@gmail.com>
 *   Copyright (C) 2008 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2008 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2007 Carsten Valdemar Munk <carsten.munk+inspircd@gmail.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>

/* $CompileFlags: */
/* $LinkerFlags: -lcurl */

struct memory_struct {
    char *memory;
    size_t size;
};


class ModuleCrowdAuth : public Module
{
	LocalIntExt crowdAuthed;
	std::string crowdurl;
	std::string appname;
	std::string app_password;
        std::string killreason;
        std::string allowpattern;
	bool verbose;
	bool useusername;

private:
        void cleanup_curl(CURL *curl_session) {
            if (curl_session != NULL) {
                curl_easy_cleanup(curl_session);
            }

            curl_global_cleanup();
        }

        static size_t write_memory_cb(void *contents, size_t size, size_t nmemb, void *userptr) {
            size_t content_length = size * nmemb;
            struct memory_struct *mem = (struct memory_struct *) userptr;
            size_t new_memory_size = mem->size + content_length + size;

            mem->memory = (char *) realloc(mem->memory, new_memory_size);
            if (mem->memory == NULL) {
                printf("Not enough memory to realloc -- returned NULL\n");
                return 0;
            }

            memcpy( &(mem->memory[mem->size]), contents, content_length );
            mem->size += content_length;
            mem->memory[mem->size] = 0;

            return content_length;
        }

        static size_t read_memory_cb(void *dest, size_t size, size_t nmemb, void *userptr) {
            struct memory_struct *userdata = (struct memory_struct *) userptr;
            
            if (size*nmemb < 1) {
                return 0;
            }

            if (! userdata->size) {
                return 0;
            }
            
            *(char *) dest = userdata->memory[0];
            userdata->memory++;
            userdata->size--;
            return 1;
        }

        static CURLcode set_http_basic_auth(CURL *curl_session, const char *username, const char *password) {
            CURLcode setopt_result;

            setopt_result = curl_easy_setopt(curl_session, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            if (setopt_result != CURLE_OK) {
                printf("Failed to set CURLOPT_HTTPAUTH\n");
                return setopt_result;
            }

            setopt_result = curl_easy_setopt(curl_session, CURLOPT_USERNAME, username);
            if (setopt_result != CURLE_OK) {
                printf("Failed to set CURLOPT_USERNAME\n");
                return setopt_result;
            }

            setopt_result = curl_easy_setopt(curl_session, CURLOPT_PASSWORD, password);
            if (setopt_result != CURLE_OK) {
                printf("Failed to set CURLOPT_PASSWORD\n");
                return setopt_result;
            }

            return CURLE_OK;
        }

        bool authenticate_crowd_user(const std::string &username, const std::string &password)
        {
            CURL *curl_session;
            CURLcode res;
            struct memory_struct http_response_header;
            struct memory_struct http_response_body;
            struct memory_struct http_request_body;
            struct curl_slist *http_request_headers = NULL;

            char body_buffer[1024];
            snprintf(body_buffer, 1024, "{ \"value\": \"%s\"}\r\n", password.c_str());
	    ServerInstance->SNO->WriteToSnoMask('c', "DEBUG: Body buffer is %s", body_buffer);

            http_request_body.memory = body_buffer;
            http_request_body.size = strlen(body_buffer);

            char header_buffer[1024];
            snprintf(header_buffer, 1024, "Content-Length: %ld", http_request_body.size);
	    ServerInstance->SNO->WriteToSnoMask('c', "DEBUG: Header buffer is %s", header_buffer);

            http_request_headers = curl_slist_append(http_request_headers, "Content-Type: application/json");
            http_request_headers = curl_slist_append(http_request_headers, "Accept: application/json");
            http_request_headers = curl_slist_append(http_request_headers, header_buffer);

            http_response_header.memory = (char *) malloc(1);
            http_response_header.size = 0;

            http_response_body.memory = (char *) malloc(1);
            http_response_body.size = 0;

            if (curl_global_init(CURL_GLOBAL_SSL) != 0) {
                printf("curl_global_init() retuned non-zero.\n");
                return false;
            }

            curl_session = curl_easy_init();
            if (curl_session == NULL) {
                printf("curl_easy_init() returned NULL.\n");
                cleanup_curl(curl_session);
                return false;
            }

            set_http_basic_auth(curl_session, appname.c_str(), app_password.c_str());

            char url_buffer[1024];
            snprintf(url_buffer, 1024, "%s/usermanagement/latest/authentication?username=%s", 
                    crowdurl.c_str(), 
                    username.c_str());
	    ServerInstance->SNO->WriteToSnoMask('c', "DEBUG: URL is %s", url_buffer);

            curl_easy_setopt(curl_session, CURLOPT_URL, url_buffer);
            curl_easy_setopt(curl_session, CURLOPT_POST, 1L);
            curl_easy_setopt(curl_session, CURLOPT_READDATA, (void *) &http_request_body);
            curl_easy_setopt(curl_session, CURLOPT_READFUNCTION, read_memory_cb);
            curl_easy_setopt(curl_session, CURLOPT_HTTPHEADER, http_request_headers);
            curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, write_memory_cb);
            curl_easy_setopt(curl_session, CURLOPT_WRITEHEADER, (void *) &http_response_header);
            curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, (void *) &http_response_body);

            curl_easy_setopt(curl_session, CURLOPT_VERBOSE, 1L);
            
            res = curl_easy_perform(curl_session);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                return false;
            }

            long http_response_status = 0;
            curl_easy_getinfo(curl_session, CURLINFO_RESPONSE_CODE, &http_response_status);
            if (http_response_status != 200) {
                //printf("Authentication FAILED!\n");
                return false;
            }

            //printf("HTTP response:\n");
            //printf("%s", http_response_header.memory); 
            //printf("---\n"); 
            //printf("%s\n", http_response_body.memory); 
            
            // TODO: Cleanup http_response_content
            cleanup_curl(curl_session);
            return true;
        }

public:
	ModuleCrowdAuth() : crowdAuthed("crowdauth", this)
	{
	}

	~ModuleCrowdAuth()
	{
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("crowdauth");
                /* URL: http / https */
                /* URL: host */
                /* URL: port */
                /* appname */
                /* app password */
                crowdurl = tag->getString("crowdurl");
                appname = tag->getString("appname");
                app_password = tag->getString("password");
		killreason = tag->getString("killreason");
                allowpattern = tag->getString("allowpattern");
                // Set to true if failed connects should be reported to operators
		verbose			= tag->getBool("verbose");
                // Will try both nick and username if this is true, otherwise only nick	
		useusername		= tag->getBool("userfield");

		Connect();
	}

	bool Connect()
	{
                //TODO(tlan): We can use this to verify crowd connectivity
		return true;
	}

	ModResult OnUserRegister(LocalUser* user) CXX11_OVERRIDE
	{
                // Note this is their initial (unresolved) connect block
                ConfigTag* tag = user->MyClass->config;
                if (!tag->getBool("usecrowdauth", true))
                        return MOD_RES_PASSTHRU;

                // default to not authenticated
		crowdAuthed.set(user,0);

		if (!allowpattern.empty() && InspIRCd::Match(user->nick, allowpattern))
		{
			crowdAuthed.set(user,1);
			return MOD_RES_PASSTHRU;
		}

		if (!CheckCredentials(user))
		{
			ServerInstance->Users->QuitUser(user, killreason);
			return MOD_RES_DENY;
		}

		return MOD_RES_PASSTHRU;
	}

        /*
        Supports:
        * nick / password
        * username:password as password
        * username@somewhere / password (will strip anything after @)
        */
	bool CheckCredentials(LocalUser* user)
	{
	        if (!Connect())
		        return false;

		if (user->password.empty())
		{
			if (verbose)
				ServerInstance->SNO->WriteToSnoMask('c', "Forbidden connection from %s (No password provided)", user->GetFullRealHost().c_str());
			return false;
		}
                
                //First we try nick/password, then we try using username from userfield
                if (authenticate_crowd_user(user->nick, user->password)) {
                    crowdAuthed.set(user, 1);
                    return true;
                }
                
                std::string username = user->ident;
                std::size_t cut_idx = username.find("@");
                if (cut_idx != std::string::npos) {
                    username.erase(cut_idx, username.size());
                }
		ServerInstance->SNO->WriteToSnoMask('c', "DEBUG: Username is %s", username.c_str());
                if (authenticate_crowd_user(username, user->password)) {
                    crowdAuthed.set(user, 1);
                    return true;
                }

                return false;
	}

	ModResult OnCheckReady(LocalUser* user) CXX11_OVERRIDE
	{
		return crowdAuthed.get(user) ? MOD_RES_PASSTHRU : MOD_RES_DENY;
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Allow/deny users based on CROWD authentication", VF_VENDOR);
	}
};

MODULE_INIT(ModuleCrowdAuth)
