


#include <glib.h>
#include <purple.h>

#include <http.h>
#include "purplecompat.h"

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#define IG_VERSION           "27.0.0.7.97"
#define SIG_KEY_VERSION      "4"
#define IG_SIG_KEY           "109513c04303341a7daf27bb41b268e633b30dcc65a3fe14503f743176113869"
#define INSTAGRAM_USERAGENT  "Instagram 27.0.0.7.97 Android (22/6.0.1; 577dpi; 1440x2560; LGE; LG-P990; p990_505-xxx; en_US)"
#define IG_URL_PREFIX        "https://i.instagram.com/api/v1"

#ifndef _
#	define _(a) (a)
#endif



#include <json-glib/json-glib.h>

// Suppress overzealous json-glib 'critical errors'
#define json_object_has_member(JSON_OBJECT, MEMBER) \
	(JSON_OBJECT ? json_object_has_member(JSON_OBJECT, MEMBER) : FALSE)
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)

#define json_array_get_length(JSON_ARRAY) \
	(JSON_ARRAY ? json_array_get_length(JSON_ARRAY) : 0)

static gchar *
json_object_to_string(JsonObject *obj)
{
	JsonNode *node;
	gchar *str;
	JsonGenerator *generator;

	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, obj);

	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, NULL);
	g_object_unref(generator);
	json_node_free(node);

	return str;
}


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;

	GHashTable *cookie_table;

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gchar *challenge_url;
} InstagramAccount;


typedef void (*InstagramProxyCallbackFunc)(InstagramAccount *ia, JsonNode *node, gpointer user_data);

typedef struct {
	InstagramAccount *ia;
	InstagramProxyCallbackFunc callback;
	gpointer user_data;
} InstagramProxyConnection;

static int
gc_hmac_sha256(const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf)
{
#if PURPLE_VERSION_CHECK(3, 0, 0)
	GHmac *hmac;
	
	hmac = g_hmac_new(G_CHECKSUM_SHA256, key, keylen);
	g_hmac_update(hmac, in, inlen);
	g_hmac_get_digest(hmac, resbuf, 32);
	g_hmac_unref(hmac);
	
#else
	PurpleCipherContext *hmac;
	
	hmac = purple_cipher_context_new_by_name("hmac", NULL);

	purple_cipher_context_set_option(hmac, "hash", "sha256");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, keylen);
	purple_cipher_context_append(hmac, (guchar *)in, inlen);
	purple_cipher_context_digest(hmac, 32, resbuf, NULL);
	purple_cipher_context_destroy(hmac);
	
#endif
	
	return 1;
}

gchar *
ig_generate_signature(const gchar *data)
{
	static guchar sig[33];

	gc_hmac_sha256(IG_SIG_KEY, strlen(IG_SIG_KEY), data, strlen(data), sig);
	sig[32] = '\0';
	
	return purple_base16_encode(sig, 32);
}

gchar *
ig_generate_signature_for_post(const gchar *data)
{
	gchar *sig = ig_generate_signature(data);
	gchar *ret = g_strdup_printf("ig_sig_key_version=" SIG_KEY_VERSION "&signed_body=%s.%s",
				sig, purple_url_encode(data));
	g_free(sig);
	return ret;
}



static void
ig_update_cookies(InstagramAccount *ia, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;

	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur)) {
		cookie_start = cur->data;

		cookie_end = strchr(cookie_start, '=');

		if (cookie_end != NULL) {
			cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');

			if (cookie_end != NULL) {
				cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
				cookie_start = cookie_end;

				g_hash_table_replace(ia->cookie_table, cookie_name, cookie_value);
			}
		}
	}
}

static void
ig_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
ig_cookies_to_string(InstagramAccount *ia)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ia->cookie_table, (GHFunc) ig_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
ig_response_callback(PurpleHttpConnection *http_conn,
						  PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
	const gchar *error_message = purple_http_response_get_error(response);
	const gchar *body;
	gsize body_len;
	InstagramProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();

	conn->ia->http_conns = g_slist_remove(conn->ia->http_conns, http_conn);

	ig_update_cookies(conn->ia, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;

	if (body == NULL && error_message != NULL) {
		/* connection error - unersolvable dns name, non existing server */
		gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
		purple_connection_error(conn->ia->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
		g_free(error_msg_formatted);
		g_free(conn);
		return;
	}

	if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
		if (conn->callback) {
			JsonNode *dummy_node = json_node_new(JSON_NODE_OBJECT);
			JsonObject *dummy_object = json_object_new();

			json_node_set_object(dummy_node, dummy_object);
			json_object_set_string_member(dummy_object, "body", body);
			json_object_set_int_member(dummy_object, "len", body_len);
			g_dataset_set_data(dummy_node, "raw_body", (gpointer) body);

			conn->callback(conn->ia, dummy_node, conn->user_data);

			g_dataset_destroy(dummy_node);
			json_node_free(dummy_node);
			json_object_unref(dummy_object);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);

		purple_debug_misc("instagram", "Got response: %s\n", body);

		if (conn->callback) {
			conn->callback(conn->ia, root, conn->user_data);
		}
	}

	g_object_unref(parser);
	g_free(conn);
}

static void
ig_fetch_url_with_method(InstagramAccount *ia, const gchar *method, const gchar *url, const gchar *postdata, InstagramProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	InstagramProxyConnection *conn;
	gchar *cookies;
	PurpleHttpConnection *http_conn;

	account = ia->account;

	if (purple_account_is_disconnected(account)) {
		return;
	}

	conn = g_new0(InstagramProxyConnection, 1);
	conn->ia = ia;
	conn->callback = callback;
	conn->user_data = user_data;

	cookies = ig_cookies_to_string(ia);

	if (method == NULL) {
		method = "GET";
	}

	purple_debug_info("instagram", "Fetching url %s\n", url);


	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_set_method(request, method);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", INSTAGRAM_USERAGENT);
	purple_http_request_header_set(request, "X-IG-Connection-Type", "WIFI");
	purple_http_request_header_set(request, "X-IG-Capabilities", "3QI=");
	purple_http_request_header_set(request, "Cookie", cookies);

	if (postdata) {
		if (strstr(url, "/login") && strstr(postdata, "password")) {
			purple_debug_info("instagram", "With postdata ###PASSWORD REMOVED###\n");
		} else {
			purple_debug_info("instagram", "With postdata %s\n", postdata);
		}

		purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		
		if (postdata[0] == '{') {
			gchar *sig = ig_generate_signature_for_post(postdata);
			purple_http_request_set_contents(request, sig, -1);
			g_free(sig);
		} else {
			purple_http_request_set_contents(request, postdata, -1);
		}
	}

	http_conn = purple_http_request(ia->pc, request, ig_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL) {
		ia->http_conns = g_slist_prepend(ia->http_conns, http_conn);
	}


	g_free(cookies);
}


static const char *
ig_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "instagram";
}

static GList *
ig_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static void
ig_challenge_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	
}

static void
ig_challenge_input_cb(gpointer user_data, const gchar *auth_code)
{
	InstagramAccount *ia = user_data;
	
	gchar *sec = g_strdup_printf("security_code=%s", purple_url_encode(auth_code));

	ig_fetch_url_with_method(ia, "POST", ia->challenge_url, sec, ig_challenge_cb, NULL);
	
	g_free(sec);
	g_free(ia->challenge_url);
	ia->challenge_url = NULL;
}

static void
ig_challenge_input_cancel_cb(gpointer user_data)
{
	InstagramAccount *ia = user_data;
	purple_connection_error(ia->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, 
		_("User cancelled challenge"));
}

static void
ig_login_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		
		if (json_object_get_boolean_member(response, "invalid_credentials")) {
			purple_debug_error("instagram", "%s\n", json_object_get_string_member(response, "message"));
			
		} else if (purple_strequal(json_object_get_string_member(response, "error_type"), "checkpoint_challenge_required")) {
			JsonObject *challenge = json_object_get_object_member(response, "challenge");
			const gchar *challenge_api_path = json_object_get_string_member(challenge, "api_path");
			//"api_path": "/challenge/1234567890/asdfgqwert/",
			
			ia->challenge_url = g_strdup_printf("%s%s", IG_URL_PREFIX, challenge_api_path);
			ig_fetch_url_with_method(ia, "POST", ia->challenge_url, "choice=1", NULL, NULL);
			
			purple_request_input(ia->pc, _("Login challenge"),
								_("Enter the six-digit code sent to your email"),
								NULL,
								NULL, FALSE, FALSE, "",
								_("OK"), G_CALLBACK(ig_challenge_input_cb), 
								_("Cancel"), G_CALLBACK(ig_challenge_input_cancel_cb), 
								purple_request_cpar_from_connection(ia->pc),
								ia);
		}
	}
}
		
static void
ig_login(PurpleAccount *account)
{
	InstagramAccount *ia;
	PurpleConnection *pc = purple_account_get_connection(account);
	
	ia = g_new0(InstagramAccount, 1);
	purple_connection_set_protocol_data(pc, ia);
	ia->account = account;
	ia->pc = pc;
	ia->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	//{"_csrftoken":"missing","device_id":"android-0cc175b9c0f1b6a8","_uuid":"2054c23b-c842-48e9-bcde-463192356941","username":"a","password":"a","login_attempt_count":0}
	JsonObject *obj = json_object_new();
	gchar *uuid = purple_uuid_random();
	gchar *postdata;
	
	json_object_set_string_member(obj, "_csrftoken", "missing");
	json_object_set_string_member(obj, "device_id", "android-0cc175b9c0f1b6a8");
	json_object_set_string_member(obj, "_uuid", uuid);
	json_object_set_string_member(obj, "username", purple_account_get_username(account));
	json_object_set_string_member(obj, "password", purple_connection_get_password(pc));
	json_object_set_int_member(obj, "login_attempt_count", 0);
	
	postdata = json_object_to_string(obj);
	ig_fetch_url_with_method(ia, "POST", IG_URL_PREFIX "/accounts/login/", postdata, ig_login_cb, NULL);
	
	g_free(uuid);
	g_free(postdata);
	json_object_unref(obj);
	
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
}


static void
ig_close(PurpleConnection *pc)
{
	InstagramAccount *ia = purple_connection_get_protocol_data(pc);

	g_return_if_fail(ia != NULL);

	while (ia->http_conns) {
		purple_http_conn_cancel(ia->http_conns->data);
		ia->http_conns = g_slist_delete_link(ia->http_conns, ia->http_conns);
	}

	g_hash_table_destroy(ia->cookie_table);
	ia->cookie_table = NULL;
	
	g_free(ia);
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)

// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();
	
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();
	
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);

	info = plugin->info;

	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}

	info->extra_info = prpl_info;
#if PURPLE_MINOR_VERSION >= 5
	prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
#endif
#if PURPLE_MINOR_VERSION >= 8
/* prpl_info->add_buddy_with_invite = instagram_add_buddy_with_invite; */
#endif

	// prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
	// prpl_info->protocol_options = instagram_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

	// prpl_info->get_account_text_table = instagram_get_account_text_table;
	// prpl_info->list_emblem = instagram_list_emblem;
	// prpl_info->status_text = instagram_status_text;
	// prpl_info->tooltip_text = instagram_tooltip_text;
	prpl_info->list_icon = ig_list_icon;
	// prpl_info->set_status = instagram_set_status;
	// prpl_info->set_idle = instagram_set_idle;
	prpl_info->status_types = ig_status_types;
	// prpl_info->chat_info = instagram_chat_info;
	// prpl_info->chat_info_defaults = instagram_chat_info_defaults;
	prpl_info->login = ig_login;
	prpl_info->close = ig_close;
	// prpl_info->send_im = instagram_send_im;
	// prpl_info->send_typing = instagram_send_typing;
	// prpl_info->join_chat = instagram_join_chat;
	// prpl_info->get_chat_name = instagram_get_chat_name;
	// prpl_info->find_blist_chat = instagram_find_chat;
	// prpl_info->chat_invite = instagram_chat_invite;
	// prpl_info->chat_send = instagram_chat_send;
	// prpl_info->set_chat_topic = instagram_chat_set_topic;
	// prpl_info->get_cb_real_name = instagram_get_real_name;
	// prpl_info->add_buddy = instagram_add_buddy;
	// prpl_info->remove_buddy = instagram_buddy_remove;
	// prpl_info->group_buddy = instagram_fake_group_buddy;
	// prpl_info->rename_group = instagram_fake_group_rename;
	// prpl_info->get_info = instagram_get_info;
	// prpl_info->add_deny = instagram_block_user;
	// prpl_info->rem_deny = instagram_unblock_user;

	// prpl_info->roomlist_get_list = instagram_roomlist_get_list;
	// prpl_info->roomlist_room_serialize = instagram_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	"prpl-eionrobb-instagram",		/* id */
	"Instagram",					/* name */
	"0.1",							/* version */
	"",								/* summary */
	"",								/* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	"",								/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	NULL,							/* actions */
	NULL,							/* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(instagram, plugin_init, info);

#endif