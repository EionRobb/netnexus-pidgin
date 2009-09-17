#include <glib.h>

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef G_GNUC_NULL_TERMINATED
#	if __GNUC__ >= 4
#		define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#	else
#		define G_GNUC_NULL_TERMINATED
#	endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

#ifdef _WIN32
#	include "win32dep.h"
#	define dlopen(a,b) LoadLibrary(a)
#	define RTLD_LAZY
#	define dlsym(a,b) GetProcAddress(a,b)
#	define dlclose(a) FreeLibrary(a)
#else
#	include <arpa/inet.h>
#	include <dlfcn.h>
#	include <netinet/in.h>
#	include <sys/socket.h>
#endif

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#include "accountopt.h"
#include "cipher.h"
#include "cmds.h"
#include "connection.h"
#include "debug.h"
#include "dnsquery.h"
#include "proxy.h"
#include "prpl.h"
#include "request.h"
#include "sslconn.h"
#include "version.h"
#include "xmlnode.h"

typedef struct _NetNexusConnection {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	gchar *clientId;
	gchar *gameId;
	
	PurpleProxyConnectData *conn;
	int fd;
	guint input_watcher;
	GString *rx_buf;
	
	PurpleUtilFetchUrlData *login_conn;
} NetNexusConnection;

int nn_chat_send(PurpleConnection *pc, int id, const char *message, PurpleMessageFlags flags);

void nn_refresh_room(NetNexusConnection *nnc, const gchar *channel)
{
	nn_chat_send(nnc->pc, g_str_hash(channel), "/room", PURPLE_MESSAGE_NO_LOG);
}

void nn_process_chat(NetNexusConnection *nnc, xmlnode *node)
{
	const gchar *success;
	const gchar *channel;
	const gchar *error;
	
	//<chat success="false" channel="main" error="You do not have permission to mute anyone."/>

	success = xmlnode_get_attrib(node, "success");
	channel = xmlnode_get_attrib(node, "channel");
	error = xmlnode_get_attrib(node, "error");
	
	if (g_str_equal(success, "false"))
	{
		serv_got_chat_in(nnc->pc, g_str_hash(channel), "", PURPLE_MESSAGE_ERROR, error, time(NULL));
	}
}

void nn_process_message(NetNexusConnection *nnc, xmlnode *node)
{
	const gchar *to;
	const gchar *from;
	gchar *message;
	const gchar *type;
	const gchar *success;
	const gchar *error;
	GList *chats;
	
	//<message type='notice' to='main' from='' tags=''>You have joined channel main</message>
	//<message type='chat' to='main' from='PFC-Hepburn' tags='vip'>bleep</message>
	//<message type='whisper' to='IronSinew' from='Eion' tags='member'>test</message>
	//<message type='emote' to='main' from='IronSinew' tags='admin'>IronSinew emotes</message>
	//<message type='notice' to='' from='' tags=''>Tarsonis21 is away (AFK due to inactivity)</message>
	//<message type='system' to='' from='' tags=''>system message for Eion</message>
	
	type = xmlnode_get_attrib(node, "type");
	to = xmlnode_get_attrib(node, "to");
	from = xmlnode_get_attrib(node, "from");
	success = xmlnode_get_attrib(node, "success");
	message = xmlnode_get_data(node);
	
	if (success && g_str_equal(success, "false"))
	{
		to = xmlnode_get_attrib(node, "channel");
		error = xmlnode_get_attrib(node, "error");
		serv_got_chat_in(nnc->pc, g_str_hash(to), "", PURPLE_MESSAGE_ERROR, error, time(NULL));
	} else if (to && *to)
	{
		if (g_str_equal(type, "notice"))
		{
			serv_got_chat_in(nnc->pc, g_str_hash(to), from, PURPLE_MESSAGE_SYSTEM, message, time(NULL));
			//refresh the userlist
			nn_refresh_room(nnc, to);
		} else if (g_str_equal(type, "broadcast"))
		{
			serv_got_chat_in(nnc->pc, g_str_hash(to), from, PURPLE_MESSAGE_SYSTEM, message, time(NULL));
		} else if (g_str_equal(type, "chat")) {
			serv_got_chat_in(nnc->pc, g_str_hash(to), from, PURPLE_MESSAGE_RECV, message, time(NULL));
		} else if (g_str_equal(type, "whisper")) {
			if (purple_utf8_strcasecmp(to, purple_account_get_username(nnc->account)) == 0)
			{
				serv_got_im(nnc->pc, from, message, PURPLE_MESSAGE_RECV, time(NULL));
			}
		} else if (g_str_equal(type, "emote")) {
			gchar *emote;
			emote = g_strdup_printf("/me %s", (strchr(message, ' ')?strchr(message, ' ')+1:""));
			serv_got_chat_in(nnc->pc, g_str_hash(to), from, PURPLE_MESSAGE_RECV, emote, time(NULL));
			g_free(emote);
		}
	} else {
		//Must be a global message. Display in all chats
		if (g_str_equal(type, "notice"))
		{
			//Probably a 'X is AFK' message
			//>Tarsonis21 is away (AFK due to inactivity)<
			//>Eion is no longer away.<
			//Look for all rooms that this buddy is in, and refresh the list
			purple_util_chrreplace(message, ' ', '\0');
			chats = purple_get_chats();
			for (; chats; chats = chats->next)
			{
				if (purple_conv_chat_find_user(PURPLE_CONV_CHAT(chats->data), message))
				{
					nn_refresh_room(nnc, purple_conversation_get_name(chats->data));
				}
			}
		} else if (g_str_equal(type, "system")) {
			chats = purple_get_chats();
			for (; chats; chats = chats->next)
			{
				if (purple_conversation_get_account(chats->data) == nnc->account)
				{
					serv_got_chat_in(nnc->pc, 
						purple_conv_chat_get_id(PURPLE_CONV_CHAT(chats->data)),
						from, PURPLE_MESSAGE_SYSTEM,
						message, time(NULL));
				}
			}
		}
	}
	
	g_free(message);
	
}

void nn_process_userlist(NetNexusConnection *nnc, xmlnode *node)
{
	const gchar *channel;
	const gchar *username;
	const gchar *tags;
	xmlnode *user;
	PurpleConversation *conv;
	PurpleConvChatBuddyFlags flags;
	PurpleConvChatBuddy *buddy;
	PurpleConversationUiOps *uiops;
	
	//<userlist channel='main'><user name='BmXbrigate' tags='vip,afk'/><user name="elminster' tags='member,afk'/><user name='Eion' tags='admin'/></userlist>
	channel = xmlnode_get_attrib(node, "channel");
	
	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, channel, nnc->account);
	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(conv));
	uiops = purple_conversation_get_ui_ops(conv);
	
	for(user = xmlnode_get_child(node, "user");
		user;
		user = xmlnode_get_next_twin(user))
	{
		//<user name='Eion' tags='admin'/>
		username = xmlnode_get_attrib(user, "name");
		tags = xmlnode_get_attrib(user, "tags");
		if (strstr(tags, "admin"))
			flags = PURPLE_CBFLAGS_OP;
		else if (strstr(tags, "mod"))
			flags = PURPLE_CBFLAGS_HALFOP;
		else if (strstr(tags, "vip"))
			flags = PURPLE_CBFLAGS_VOICE;
		else
			flags = PURPLE_CBFLAGS_NONE;
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), username, NULL, flags, FALSE);
		if (strstr(tags, "afk"))
		{
			purple_prpl_got_user_status(nnc->account, username, purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY), NULL);
			buddy = purple_conv_chat_cb_find(PURPLE_CONV_CHAT(conv), username);
			if (buddy != NULL)
			{
				g_free(buddy->alias);
				buddy->alias = g_strdup_printf("%s (AFK)", username);
				if (uiops && uiops->chat_rename_user)
					uiops->chat_rename_user(conv, username, username, buddy->alias);
				else if (uiops && uiops->chat_update_user)
					uiops->chat_update_user(conv, username);
			}
		} else {
			purple_prpl_got_user_status(nnc->account, username, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
		}
	}
}

void nn_process_xml(NetNexusConnection *nnc, xmlnode *node)
{
	const gchar *name;
	
	if (g_str_equal(node->name, "ping"))
	{
		//handle ping
		//<ping source="client" ct="1251973170123" st="1251973171218"/>
	} else if (g_str_equal(node->name, "userlist")) {
		//userlist
		nn_process_userlist(nnc, node);
	} else if (g_str_equal(node->name, "join")) {
		//joined a room
		//<join channel="main" success="true"/>
		name = xmlnode_get_attrib(node, "channel");
		serv_got_joined_chat(nnc->pc, g_str_hash(name), name);
		//send /channel to the channel
		//<chat type="chat" channel="main">/channel</chat>
		nn_refresh_room(nnc, name);
	} else if (g_str_equal(node->name, "leave")) {
		//left a room
		name = xmlnode_get_attrib(node, "channel");
		//<leave channel="help" success="true"/>
		serv_got_chat_left(nnc->pc, g_str_hash(name));
	} else if (g_str_equal(node->name, "message")) {
		//received a message
		nn_process_message(nnc, node);
	} else if (g_str_equal(node->name, "state")) {
		//<state name="Eion" tags="" channels="">Welcome to the netnexus chat room.</state>		
	} else if (g_str_equal(node->name, "chat")) {
		nn_process_chat(nnc, node);
	} else if (g_str_equal(node->name, "tag")) {
		purple_prpl_got_account_status(nnc->account, purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY), NULL);
	} else if (g_str_equal(node->name, "untag")) {
		purple_prpl_got_account_status(nnc->account, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
	}
}

void nn_data_in(gpointer data, gint source, PurpleInputCondition cond)
{
	NetNexusConnection *nnc = data;
	gchar buf[4096];
	ssize_t len;
	gchar *chunk;
	xmlnode *node;
	size_t chunklen;
	
	len = recv(source, buf, sizeof(buf) - 1, 0);

	if (len < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			// Try again later
			return;
		}

		close(source);
		purple_input_remove(nnc->input_watcher);
		if (nnc->rx_buf)
			g_string_free(nnc->rx_buf, TRUE);
			
		//TODO handle disconnection here
		
		return;
	}

	if (len > 0)
	{
		if (nnc->rx_buf == NULL)
			nnc->rx_buf = g_string_new("");
		
		g_string_append_len(nnc->rx_buf, buf, len);

		if (buf[len-1] != '\0')
		{
			// Wait for more data before processing
			return;
		}
	}
	
	//All data received
	//parse data

	//xml chunks are split by \0
	for (len = 0; len < nnc->rx_buf->len; len+=chunklen+1)
	{
		chunk = g_strdup(&nnc->rx_buf->str[len]);
		chunklen = strlen(chunk);
		purple_debug_info("netnexus", "received: %s\n", chunk);
		node = xmlnode_from_str(chunk, chunklen);
		nn_process_xml(nnc, node);
		xmlnode_free(node);
		g_free(chunk);
	}
	
	g_string_free(nnc->rx_buf, TRUE);
	nnc->rx_buf = NULL;
}

gint nn_char_out(NetNexusConnection *nnc, gchar *message_format, ...)
{
	va_list args;
	gchar* message;
	
	va_start(args, message_format);
	message = g_strdup_vprintf(message_format, args);
	va_end(args);
	
	purple_debug_info("netnexus", "sending: %s\n", message);
	
	return write(nnc->fd, message, strlen(message)+1);
}

gint nn_xml_out(NetNexusConnection *nnc, xmlnode *node)
{
	gchar *xml;
	gint ret;
	
	xml = xmlnode_to_str(node, NULL);
	ret = nn_char_out(nnc, xml);
	g_free(xml);
	
	return ret;
}

void nn_set_status(PurpleAccount *account, PurpleStatus *status)
{
	
}

void nn_send_xml(NetNexusConnection *nnc, xmlnode *node)//, PurpleCallback *callback, gpointer data)
{
	gint returnint;
	if (!g_str_equal(node->name, "msg"))
	{
		xmlnode *root = xmlnode_new("msg");
		xmlnode_insert_child(root, node);
		returnint = nn_char_out(nnc, xmlnode_to_str(root, NULL));
		root->child = NULL;
		root->lastchild = NULL;
		xmlnode_free(root);
	} 
}

void nn_join_chat(PurpleConnection *pc, GHashTable *components)
{
	NetNexusConnection *nnc;
	xmlnode *joinnode;
	
	nnc = pc->proto_data;
	
	joinnode = xmlnode_new("join");
	xmlnode_set_attrib(joinnode, "channel", g_hash_table_lookup(components, "channel"));
	
	nn_send_xml(nnc, joinnode);
}

static PurpleCmdRet
nn_cmd_emote(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	const gchar *channel = NULL;
	xmlnode *chatnode;
	
	pc = purple_conversation_get_gc(conv);
	channel = purple_conversation_get_name(conv);
	
	if (pc == NULL || channel == NULL)
		return PURPLE_CMD_RET_FAILED;
	
	chatnode = xmlnode_new("chat");
	xmlnode_set_attrib(chatnode, "type", "emote");
	xmlnode_set_attrib(chatnode, "channel", channel);
	if (args && args[0])
	{
		xmlnode_insert_data(chatnode, args[0], -1);
	}
	
	nn_send_xml(pc->proto_data, chatnode);
	
	return PURPLE_CMD_RET_OK;
}

void nn_chat_leave(PurpleConnection *pc, int id)
{
	//<leave channel='help'/>
	PurpleConversation *conv;
	const gchar *name;
	xmlnode *leavenode;
	
	conv = purple_find_chat(pc, id);
	name = purple_conversation_get_name(conv);
	
	leavenode = xmlnode_new("leave");
	xmlnode_set_attrib(leavenode, "channel", name);
	
	nn_send_xml(pc->proto_data, leavenode);
}

int nn_chat_send(PurpleConnection *pc, int id, const char *message, PurpleMessageFlags flags)
{
	PurpleConversation *conv;
	const gchar *name;
	xmlnode *chatnode;
	
	conv = purple_find_chat(pc, id);
	name = purple_conversation_get_name(conv);
	
	chatnode = xmlnode_new("chat");
	xmlnode_set_attrib(chatnode, "type", "chat");
	xmlnode_set_attrib(chatnode, "channel", name);
	xmlnode_insert_data(chatnode, message, -1);
	
	//<msg><chat type="chat" channel="help">1</chat></msg>
	nn_send_xml(pc->proto_data, chatnode);
	
	return 1;
}

int nn_send_im (PurpleConnection *pc, const char *who, const char *message, PurpleMessageFlags flags)
{
	//<whisper to="IronSinew">testing</whisper>
	xmlnode *whispernode;
	
	whispernode = xmlnode_new("whisper");
	xmlnode_set_attrib(whispernode, "to", who);
	xmlnode_insert_data(whispernode, message, -1);
	
	nn_send_xml(pc->proto_data, whispernode);
	
	return 1;
}

PurpleRoomlist *nn_get_roomlist(PurpleConnection *gc)
{
	
}

void nn_ping(PurpleConnection *pc)
{
	NetNexusConnection *nnc;
	gchar *timestamp_char;
	GTimeVal timestamp;
	
	nnc = pc->proto_data;
	
	g_get_current_time(&timestamp);
	timestamp_char = g_strdup_printf("%ld%ld", timestamp.tv_sec, (timestamp.tv_usec/1000));
	
	xmlnode *pingnode = xmlnode_new("ping");
	xmlnode_set_attrib(pingnode, "source", "client");
	xmlnode_set_attrib(pingnode, "ct", timestamp_char);
	
	nn_send_xml(nnc, pingnode);
	
	g_free(timestamp_char);
}


GList *
nn_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("Channel");
	pce->identifier = "channel";
	pce->required = TRUE;
	m = g_list_append(m, pce);
	
	return m;
}

GHashTable *
nn_chat_info_defaults(PurpleConnection *pc, const char *chat_name)
{
	GHashTable *defaults;
	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	if (chat_name != NULL)
	{
		g_hash_table_insert(defaults, "channel", g_strdup(chat_name));
	}
	return defaults;
}

void nn_login_cb(gpointer data, gint source, const gchar *error_message)
{
	NetNexusConnection *nnc = data;
	if (error_message)
	{
		purple_debug_error("netnexus", "login_cb %s\n", error_message);
		purple_connection_error_reason(nnc->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Server closed the connection."));
		return;
	}

	purple_debug_info("nexnexus", "login_cb\n");
	nnc->fd = source;
	
	purple_connection_set_state(nnc->pc, PURPLE_CONNECTED);
	purple_connection_update_progress(nnc->pc, _("Connected"), 4, 4);
	
	nn_char_out(nnc, "<connect clientId='%s' gameId='%s'/>", nnc->clientId, nnc->gameId);
	
	nnc->input_watcher = purple_input_add(nnc->fd, PURPLE_INPUT_READ, nn_data_in, nnc);
}

void nn_http_login2_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	NetNexusConnection *nnc;
	xmlnode *response;
	xmlnode *gidnode, *cidnode;
	gchar *gid, *cid;
	
	nnc = user_data;
	nnc->login_conn = NULL;
	
	response = xmlnode_from_str(url_text, len);
	
	//TODO check that there's not an error
	
	gidnode = xmlnode_get_child(response, "gid");
	cidnode = xmlnode_get_child(response, "cid");
	
	gid = xmlnode_get_data_unescaped(gidnode);
	cid = xmlnode_get_data_unescaped(cidnode);
	
	nnc->clientId = cid;
	nnc->gameId = gid;
	
	xmlnode_free(response);
	
	purple_connection_set_state(nnc->pc, PURPLE_CONNECTING);
	purple_connection_update_progress(nnc->pc, _("Connecting to chat server"), 3, 4);
	
	purple_proxy_connect(nnc, nnc->account, "ugp.netnexus.com", 9867, nn_login_cb, nnc);
}

void nn_http_login_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gchar md5Hash[33];
	NetNexusConnection *nnc;
	xmlnode *response, *keynode;
	gchar *key;
	gchar *user, *pass;
	gchar *url;
	gchar *unenc;
	
	nnc = user_data;
	nnc->login_conn = NULL;
	
	purple_connection_set_state(nnc->pc, PURPLE_CONNECTING);
	purple_connection_update_progress(nnc->pc, _("Authenticating"), 2, 3);
	
	response = xmlnode_from_str(url_text, len);
	
	//TODO check that there's not an error
	
	keynode = xmlnode_get_child(response, "key");
	
	key = xmlnode_get_data_unescaped(keynode);
	user = g_strdup(purple_url_encode(nnc->account->username));
	
	cipher = purple_ciphers_find_cipher("md5");
	context = purple_cipher_context_new(cipher, NULL);

	unenc = g_strdup_printf("%s%s", nnc->account->password, key);
	purple_cipher_context_append(context, (guchar *)unenc, strlen(unenc));
	purple_cipher_context_digest_to_str(context, sizeof(md5Hash), md5Hash, NULL);
	purple_cipher_context_destroy(context);
	pass = g_strdup(purple_url_encode(md5Hash));
	
	url = g_strdup_printf("http://ugp.netnexus.com/games/babbleon/external.php?task=auth&user=%s&pass=%s", user, pass);
	nnc->login_conn = purple_util_fetch_url(url, TRUE, NULL, TRUE, nn_http_login2_cb, nnc);
	
	xmlnode_free(response);
	g_free(key);
	g_free(url);
	g_free(user);
	g_free(pass);
	g_free(unenc);
}

void nn_login(PurpleAccount *account)
{
	PurpleConnection *pc;
	NetNexusConnection *nnc;
	gchar *url;
	
	pc = purple_account_get_connection(account);
	
	nnc = g_new0(NetNexusConnection, 1);
	nnc->account = account;
	nnc->pc = pc;
	pc->proto_data = nnc;
	
	purple_connection_set_state(pc, PURPLE_CONNECTING);
	purple_connection_update_progress(pc, _("Connecting to login server"), 1, 3);
	
	url = g_strdup_printf("http://ugp.netnexus.com/games/babbleon/external.php?task=start&user=%s", purple_url_encode(account->username));
	nnc->login_conn = purple_util_fetch_url(url, TRUE, NULL, TRUE, nn_http_login_cb, nnc);
	
	g_free(url);
}

void nn_close(PurpleConnection *pc)
{
	NetNexusConnection *nnc;
	
	nnc = pc->proto_data;
	
	if (!nnc)
		return;
	
	nn_char_out(nnc, "<msg><close>Quit</close></msg>");
	
	if (nnc->login_conn)
		purple_util_fetch_url_cancel(nnc->login_conn);
	
	close(nnc->fd);
	purple_input_remove(nnc->input_watcher);
	g_string_free(nnc->rx_buf, TRUE);
	
	g_free(nnc->clientId);
	g_free(nnc->gameId);
	g_free(nnc);
	
}

static const char *nn_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "netnexus";
}

static GList *nn_statuses(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	//afk
	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static gboolean plugin_load(PurplePlugin *plugin)
{
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin)
{
	return TRUE;
}

static void plugin_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	PurplePluginProtocolInfo *prpl_info = info->extra_info;
	
	option = purple_account_option_bool_new(_("HTTP Connection Method"), "netnexus_http_connect", FALSE);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
	
	purple_cmd_register("me", "s", PURPLE_CMD_P_PRPL, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						plugin->info->id, nn_cmd_emote,
						_("me: Emote"),
						NULL);
	purple_cmd_register("emote", "s", PURPLE_CMD_P_PRPL, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						plugin->info->id, nn_cmd_emote,
						_("me: Emote"),
						NULL);
	
}

static PurplePluginProtocolInfo prpl_info = {
	/* options */
	OPT_PROTO_UNIQUE_CHATNAME,

	NULL,                   /* user_splits */
	NULL,                   /* protocol_options */
	NO_BUDDY_ICONS          /* icon_spec */
	/*{"jpg", 0, 0, 50, 50, -1, PURPLE_ICON_SCALE_SEND}*/, /* icon_spec */
	nn_list_icon,           /* list_icon */
	NULL,                   /* list_emblems */
	NULL,                   /* status_text */
	NULL,                   /* tooltip_text */
	nn_statuses,            /* status_types */
	NULL,                   /* blist_node_menu */
	nn_chat_info,           /* chat_info */
	nn_chat_info_defaults,  /* chat_info_defaults */
	nn_login,               /* login */
	nn_close,               /* close */
	nn_send_im,             /* send_im */
	NULL,                   /* set_info */
	NULL,                   /* send_typing */
	NULL,                   /* get_info */
	nn_set_status,          /* set_status */
	NULL,                   /* set_idle */
	NULL,                   /* change_passwd */
	NULL,                   /* add_buddy */
	NULL,                   /* add_buddies */
	NULL,                   /* remove_buddy */
	NULL,                   /* remove_buddies */
	NULL,                   /* add_permit */
	NULL,                   /* add_deny */
	NULL,                   /* rem_permit */
	NULL,                   /* rem_deny */
	NULL,                   /* set_permit_deny */
	nn_join_chat,           /* join_chat */
	NULL,                   /* reject chat invite */
	NULL,                   /* get_chat_name */
	NULL,                   /* chat_invite */
	nn_chat_leave,          /* chat_leave */
	NULL,                   /* chat_whisper */
	nn_chat_send,           /* chat_send */
	nn_ping,                /* keepalive */
	NULL,                   /* register_user */
	NULL,                   /* get_cb_info */
	NULL,                   /* get_cb_away */
	NULL,                   /* alias_buddy */
	NULL,                   /* group_buddy */
	NULL,                   /* rename_group */
	NULL,                   /* buddy_free */
	NULL,                   /* convo_closed */
	purple_normalize_nocase,/* normalize */
	NULL,                   /* set_buddy_icon */
	NULL,                   /* remove_group */
	NULL,                   /* get_cb_real_name */
	NULL,                   /* set_chat_topic */
	NULL,                   /* find_blist_chat */
	nn_get_roomlist,        /* roomlist_get_list */
	NULL,                   /* roomlist_cancel */
	NULL,                   /* roomlist_expand_category */
	NULL,                   /* can_receive_file */
	NULL,                   /* send_file */
	NULL,                   /* new_xfer */
	NULL,                   /* offline_message */
	NULL,                   /* whiteboard_prpl_ops */
	NULL,//nn_char_out,            /* send_raw */
	NULL,                   /* roomlist_room_serialize */
	NULL,                   /* unregister_user */
	NULL,                   /* send_attention */
	NULL,                   /* attention_types */
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL,                   /* get_account_text_table */
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	2, /* major_version */
	3, /* minor version */
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	"prpl-bigbrownchunx-netnexus", /* id */
	"NetNexus Chat", /* name */
	"0.1", /* version */
	N_("NetNexus Chat Protocol Plugin"), /* summary */
	N_("NetNexus Chat Protocol Plugin"), /* description */
	"Eion Robb <eionrobb@gmail.com>", /* author */
	"", /* homepage */
	plugin_load, /* load */
	plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	&prpl_info, /* extra_info */
	NULL, /* prefs_info */
	NULL, /* actions */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(okcupid, plugin_init, info);
