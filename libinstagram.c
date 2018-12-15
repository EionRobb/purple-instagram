


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
	GHashTable *user_ids;

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gchar *challenge_url;
	gchar *csrftoken;
	gchar *device_id;
	gint64 last_message_timestamp;
	
	guint heartbeat_timeout;
	PurpleHttpKeepalivePool *keepalive_pool;
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
				
				if (purple_strequal(cookie_name, "csrftoken")) {
					g_free(ia->csrftoken);
					ia->csrftoken = g_strdup(cookie_value);
				}
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
		/* connection error - unresolvable dns name, non existing server */
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
	
	purple_http_request_set_keepalive_pool(request, ia->keepalive_pool);

	http_conn = purple_http_request(ia->pc, request, ig_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL) {
		ia->http_conns = g_slist_prepend(ia->http_conns, http_conn);
	}


	g_free(cookies);
}

static PurpleGroup *
ig_get_or_create_default_group()
{
	PurpleGroup *ig_group = purple_blist_find_group("Instagram");

	if (!ig_group) {
		ig_group = purple_group_new("Instagram");
		purple_blist_add_group(ig_group, NULL);
	}

	return ig_group;
}

static void ig_find_user(InstagramAccount *ia, const gchar *username, InstagramProxyCallbackFunc callback, gpointer user_data);
static void ig_add_buddy_from_json(InstagramAccount *ia, JsonObject *user);

static void
ig_got_info(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	JsonObject *user = json_object_get_object_member(obj, "user");
	PurpleNotifyUserInfo *user_info;
	const gchar *username = json_object_get_string_member(user, "username");
	
	user_info = purple_notify_user_info_new();
	
	gchar *num_str = g_strdup_printf("%u", (guint) json_object_get_int_member(user, "pk"));
	purple_notify_user_info_add_pair_html(user_info, _("ID"), num_str);
	g_free(num_str);
	
	purple_notify_user_info_add_pair_html(user_info, _("Username"), username);
	purple_notify_user_info_add_pair_html(user_info, _("Full name"), json_object_get_string_member(user, "full_name"));
	purple_notify_user_info_add_pair_html(user_info, _("Verified?"), json_object_get_boolean_member(user, "is_verified") ? _("Yes") : _("No"));
	
	num_str = g_strdup_printf("%u", (guint) json_object_get_int_member(user, "follower_count"));
	purple_notify_user_info_add_pair_html(user_info, _("Followers"), num_str);
	g_free(num_str);
	num_str = g_strdup_printf("%u", (guint) json_object_get_int_member(user, "following_count"));
	purple_notify_user_info_add_pair_html(user_info, _("Following"), num_str);
	g_free(num_str);
	
	purple_notify_user_info_add_section_break(user_info);
	
	purple_notify_user_info_add_pair_html(user_info, _("Bio"), json_object_get_string_member(user, "biography"));
	purple_notify_user_info_add_pair_html(user_info, _("URL"), json_object_get_string_member(user, "external_url"));
	
	purple_notify_userinfo(ia->pc, username, user_info, NULL, NULL);
}

static void
ig_get_info_by_id(PurpleConnection *pc, gint pk)
{
	InstagramAccount *ia = purple_connection_get_protocol_data(pc);
	gchar *url = g_strdup_printf(IG_URL_PREFIX "/users/%u/info/", (guint) pk);
	
	ig_fetch_url_with_method(ia, "GET", url, NULL, ig_got_info, NULL);
}

static void
ig_get_info_found_user(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	gint pk = (gint) json_object_get_int_member(obj, "pk");
	
	ig_get_info_by_id(ia->pc, pk);
}

static void
ig_get_info(PurpleConnection *pc, const gchar *who)
{
	InstagramAccount *ia = purple_connection_get_protocol_data(pc);
	gint pk = 0;
	
	pk = GPOINTER_TO_INT(g_hash_table_lookup(ia->user_ids, who));
	
	if (pk == 0) {
		PurpleBuddy *buddy = purple_blist_find_buddy(ia->account, who);
		
		if (buddy != NULL) {
			PurpleBlistNode *blistnode = PURPLE_BLIST_NODE(buddy);
			pk = purple_blist_node_get_int(blistnode, "pk");
			
			g_hash_table_replace(ia->user_ids, g_strdup(who), GINT_TO_POINTER(pk));
		}
	}
	
	if (pk != 0) {
		ig_get_info_by_id(pc, pk);
	} else {
		ig_find_user(ia, who, ig_get_info_found_user, NULL);
	}
}

static void
ig_add_buddy_found_user(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	ig_add_buddy_from_json(ia, json_node_get_object(node));
}

static void
ig_add_buddy_with_invite(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message)
{
	InstagramAccount *ia = purple_connection_get_protocol_data(pc);
	const gchar *who = purple_buddy_get_name(buddy);
	
	ig_find_user(ia, who, ig_add_buddy_found_user, NULL);
}
	
static void
ig_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	ig_add_buddy_with_invite(pc, buddy, group, NULL);
}

static void
ig_send_im_found_user(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	
	gchar *message = user_data;
	
	if (node != NULL) {
		GString *postdata = g_string_new(NULL);
		gchar *uuid = purple_uuid_random();
		gchar *context = purple_uuid_random();
		gint64 pk = json_object_get_int_member(obj, "pk");
		
		g_string_append_printf(postdata, "_csrftoken=%s&", purple_url_encode(ia->csrftoken));
		g_string_append_printf(postdata, "device_id=%s&", purple_url_encode(ia->device_id));
		g_string_append_printf(postdata, "_uuid=%s&", purple_url_encode(uuid));
		g_string_append_printf(postdata, "recipient_users=[[%u]]&", (guint) pk);
		g_string_append_printf(postdata, "client_context=%s&", purple_url_encode(context));
		g_string_append_printf(postdata, "text=%s&", purple_url_encode(message));
		
		ig_fetch_url_with_method(ia, "POST", IG_URL_PREFIX "/direct_v2/threads/broadcast/text/", postdata->str, NULL /* TODO check response */, NULL);
		
		//TODO store context into hashtable
		g_free(context);
		g_free(uuid);
		g_string_free(postdata, TRUE);
		
	} else {
		//purple_conversation_present_error(who, da->account, _("Unknown user, cannot send."));
	
	}
	
	g_free(message);
}

static int
ig_send_im(PurpleConnection *pc,
#if PURPLE_VERSION_CHECK(3, 0, 0)
				PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
				const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	InstagramAccount *ia = purple_connection_get_protocol_data(pc);
	gint pk = 0;
	
	pk = GPOINTER_TO_INT(g_hash_table_lookup(ia->user_ids, who));
	
	if (pk == 0) {
		PurpleBuddy *buddy = purple_blist_find_buddy(ia->account, who);
		
		if (buddy != NULL) {
			PurpleBlistNode *blistnode = PURPLE_BLIST_NODE(buddy);
			pk = purple_blist_node_get_int(blistnode, "pk");
			
			g_hash_table_replace(ia->user_ids, g_strdup(who), GINT_TO_POINTER(pk));
		}
	}
	
	if (pk != 0) {
		//https://i.instagram.com/api/v1/direct_v2/threads/broadcast/text/
		GString *postdata = g_string_new(NULL);
		gchar *uuid = purple_uuid_random();
		gchar *context = purple_uuid_random();
		
		g_string_append_printf(postdata, "_csrftoken=%s&", purple_url_encode(ia->csrftoken));
		g_string_append_printf(postdata, "device_id=%s&", purple_url_encode(ia->device_id));
		g_string_append_printf(postdata, "_uuid=%s&", purple_url_encode(uuid));
		g_string_append_printf(postdata, "recipient_users=[[%u]]&", (guint) pk);
		g_string_append_printf(postdata, "client_context=%s&", purple_url_encode(context));
		g_string_append_printf(postdata, "text=%s&", purple_url_encode(message));
		
		ig_fetch_url_with_method(ia, "POST", IG_URL_PREFIX "/direct_v2/threads/broadcast/text/", postdata->str, NULL /* TODO check response */, NULL);
		
		//TODO store context into hashtable
		g_free(context);
		g_free(uuid);
		g_string_free(postdata, TRUE);
		
		return 1;
	}
	
	ig_find_user(ia, who, ig_send_im_found_user, g_strdup(message));
	
	return 0;
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
ig_got_profile_pic(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	PurpleBuddy *buddy = user_data;

	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;
		const gchar *profile_pic_url = g_dataset_get_data(buddy, "profile_pic_url");

		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup(response_str, response_len);

		const gchar *username = purple_buddy_get_name(buddy);
		
		purple_buddy_icons_set_for_user(ia->account, username, response_dup, response_len, profile_pic_url);
	}
	
	g_dataset_destroy(buddy);
}

static void
ig_found_user(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	InstagramProxyConnection *conn = user_data;
	JsonObject *obj = json_node_get_object(node);
	JsonArray *users = json_object_get_array_member(obj, "users");
	guint users_len = json_array_get_length(users);
	const gchar *orig_username = g_dataset_get_data(conn, "username");
	guint i;
	
	for (i = 0; i < users_len; i++) {
		JsonObject *user = json_array_get_object_element(users, i);
		
		gint pk = (gint) json_object_get_int_member(user, "pk");
		const gchar *username = json_object_get_string_member(user, "username");
		
		if (purple_strequal(username, orig_username)) {
			JsonNode *user_node = json_array_get_element(users, i);
			PurpleBuddy *buddy = purple_blist_find_buddy(ia->account, username);
			
			if (buddy != NULL) {
				PurpleBlistNode *blistnode = PURPLE_BLIST_NODE(buddy);
				purple_blist_node_set_int(blistnode, "pk", pk);
			}
			
			conn->callback(ia, user_node, conn->user_data);
		}
		
		g_hash_table_replace(ia->user_ids, g_strdup(username), GINT_TO_POINTER(pk));
	}
	
	g_dataset_destroy(conn);
	
	g_free(conn);
}

static void
ig_find_user(InstagramAccount *ia, const gchar *username, InstagramProxyCallbackFunc callback, gpointer user_data) {
	gchar *url = g_strdup_printf(IG_URL_PREFIX "/users/search/?is_typehead=false&q=%s", purple_url_encode(username));
	
	InstagramProxyConnection *conn = g_new0(InstagramProxyConnection, 1);
	conn->ia = ia;
	conn->callback = callback;
	conn->user_data = user_data;
	
	g_dataset_set_data_full(conn, "username", g_strdup(username), g_free);
	
	ig_fetch_url_with_method(ia, "GET", url, NULL, ig_found_user, conn);
	
	g_free(url);
}

static void
ig_add_buddy_from_json(InstagramAccount *ia, JsonObject *user)
{
	gint pk = (gint) json_object_get_int_member(user, "pk");
	const gchar *username = json_object_get_string_member(user, "username");
	const gchar *full_name = json_object_get_string_member(user, "full_name");
	const gchar *profile_pic_url = json_object_get_string_member(user, "profile_pic_url");
	
	PurpleBuddy *buddy = purple_blist_find_buddy(ia->account, username);

	if (buddy == NULL) {
		buddy = purple_buddy_new(ia->account, username, full_name);
		purple_blist_add_buddy(buddy, NULL, ig_get_or_create_default_group(), NULL);
	}
	
	if (!json_object_get_boolean_member(user, "has_anonymous_profile_picture")) {
		const gchar *checksum = purple_buddy_icons_get_checksum_for_user(buddy);
		
		if (!purple_strequal(checksum, profile_pic_url)) {
			g_dataset_set_data_full(buddy, "profile_pic_url", g_strdup(profile_pic_url), NULL);
			ig_fetch_url_with_method(ia, "GET", profile_pic_url, NULL, ig_got_profile_pic, buddy);
		}
	}
	
	PurpleBlistNode *blistnode = PURPLE_BLIST_NODE(buddy);
	purple_blist_node_set_int(blistnode, "pk", pk);
	
	purple_protocol_got_user_status(ia->account, username, "online", NULL);
	
	g_hash_table_replace(ia->user_ids, g_strdup(username), GINT_TO_POINTER(pk));
}

static void
ig_friends_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	/*{
	"expires": 1538638782,
	"users": [{
		"pk": 25025320,
		"username": "instagram",
		"full_name": "Instagram",
		"is_private": false,
		"profile_pic_url": "https://instagram.fakl1-1.fna.fbcdn.net/vp/ca89afc73ba2b787ed1621db3f534ea6/5C150A5B/t51.2885-19/s150x150/14719833_310540259320655_1605122788543168512_a.jpg",
		"profile_pic_id": "1360316971354486387_25025320",
		"friendship_status": {
			"following": true,
			"is_private": false,
			"incoming_request": false,
			"outgoing_request": false,
			"is_bestie": false
		},
		"is_verified": true,
		"has_anonymous_profile_picture": false,
		"reel_auto_archive": "on"
	}],
	"status": "ok"
	*/
	JsonObject *obj = json_node_get_object(node);
	JsonArray *users = json_object_get_array_member(obj, "users");
	gint i;
	
	for (i = json_array_get_length(users) - 1; i >= 0; i--) {
		JsonObject *user = json_array_get_object_element(users, i);
		
		ig_add_buddy_from_json(ia, user);
	}
	
}

static void
ig_thread_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	JsonObject *thread = json_object_get_object_member(obj, "thread");
	gint last_message_timestamp = GPOINTER_TO_INT(user_data);
	
	if (!json_object_get_boolean_member(thread, "is_group")) {
		// This is a one-to-one DM
		
		JsonObject *user = json_array_get_object_element(json_object_get_array_member(thread, "users"), 0);
		gint64 user_id = json_object_get_int_member(user, "pk");
		const gchar *username = json_object_get_string_member(user, "username");
		
		JsonArray *items = json_object_get_array_member(thread, "items");
		gint i;
		for (i = json_array_get_length(items) - 1; i >= 0; i--) {
			JsonObject *item = json_array_get_object_element(items, i);
			gint64 timestamp_us = json_object_get_int_member(item, "timestamp");
			gint timestamp = (gint) (timestamp_us / 1000000);
			
			if (timestamp < last_message_timestamp) {
				continue;
			}
			
			gint64 sender = json_object_get_int_member(item, "user_id");
			const gchar *item_type = json_object_get_string_member(item, "item_type");
			const gchar *text = json_object_get_string_member(item, "text");
			
			if (purple_strequal(item_type, "text")) {
				if (sender == user_id) {
					purple_serv_got_im(ia->pc, username, text, PURPLE_MESSAGE_RECV, timestamp);
					
				} else {
					PurpleConversation *conv;
					PurpleIMConversation *imconv;
					PurpleMessage *msg;
					
					imconv = purple_conversations_find_im_with_account(username, ia->account);

					if (imconv == NULL) {
						imconv = purple_im_conversation_new(ia->account, username);
					}

					conv = PURPLE_CONVERSATION(imconv);

					if (text && *text) {
						msg = purple_message_new_outgoing(username, text, PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED);
						purple_message_set_time(msg, timestamp);
						purple_conversation_write_message(conv, msg);
						purple_message_destroy(msg);
					}
				}
			}
		}
	}
}

static void
ig_inbox_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	JsonObject *inbox = json_object_get_object_member(obj, "inbox");
	JsonArray *threads = json_object_get_array_member(inbox, "threads");
	gint i;
	gint64 max_last_activity = 0;
	gint last_message_timestamp = (gint) (ia->last_message_timestamp / 1000000);
	
	for (i = json_array_get_length(threads) - 1; i >= 0; i--) {
		JsonObject *thread = json_array_get_object_element(threads, i);
		
		if (!json_object_get_boolean_member(thread, "is_group")) {
			// This is a one-to-one DM
			JsonObject *user = json_array_get_object_element(json_object_get_array_member(thread, "users"), 0);
			ig_add_buddy_from_json(ia, user);
		}
		
		//Use last_activity_at to work out if there's a newer message
		gint64 last_activity_at = json_object_get_int_member(thread, "last_activity_at");
		if (ia->last_message_timestamp && last_activity_at > ia->last_message_timestamp) {
			const gchar *thread_id = json_object_get_string_member(thread, "thread_id");
			gchar *thread_url = g_strdup_printf(IG_URL_PREFIX "/direct_v2/threads/%s/", thread_id);
			ig_fetch_url_with_method(ia, "GET", thread_url, NULL, ig_thread_cb, GINT_TO_POINTER(last_message_timestamp));
			
		}
		max_last_activity = MAX(max_last_activity, last_activity_at);
	}
	
	purple_account_set_int(ia->account, "last_message_timestamp_high", max_last_activity >> 32);
	purple_account_set_int(ia->account, "last_message_timestamp_low", max_last_activity & 0xFFFFFFFF);
	ia->last_message_timestamp = max_last_activity;
}

static gboolean
ig_inbox_polling(gpointer userdata)
{
	InstagramAccount *ia = userdata;
	
	ig_fetch_url_with_method(ia, "GET", IG_URL_PREFIX "/direct_v2/inbox/", NULL, ig_inbox_cb, NULL);

	return TRUE;
}

static void
ig_login_successful(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	purple_connection_set_state(ia->pc, PURPLE_CONNECTION_CONNECTED);
	
	ig_fetch_url_with_method(ia, "GET", IG_URL_PREFIX "/friendships/autocomplete_user_list/?version=2&followinfo=True", NULL, ig_friends_cb, NULL);
	
	ig_fetch_url_with_method(ia, "GET", IG_URL_PREFIX "/direct_v2/inbox/", NULL, ig_inbox_cb, NULL);
	ia->heartbeat_timeout = g_timeout_add_seconds(60, ig_inbox_polling, ia);
	
	if (node != NULL) {
		//TODO use self-user info for downloading own avatar and stuff
	}
}

static void
ig_challenge_cb(InstagramAccount *ia, JsonNode *node, gpointer user_data)
{
	JsonObject *response = json_node_get_object(node);
	
	if (json_object_has_member(response, "logged_in_user")) {
		ig_login_successful(ia, node, NULL);
	}
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
			//"api_path": "/challenge/1234567890/qwertyuiop/",
			
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
		} else if (json_object_has_member(response, "logged_in_user")) {
			ig_login_successful(ia, node, NULL);
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
	ia->user_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	ia->device_id = g_strdup(purple_account_get_string(ia->account, "device_id", NULL));
	ia->keepalive_pool = purple_http_keepalive_pool_new();
	
	if (ia->device_id == NULL) {
		ia->device_id = g_strdup_printf("android-%08x%08x", g_random_int(), g_random_int());
		purple_account_set_string(ia->account, "device_id", ia->device_id);
	}
	
	ia->last_message_timestamp = purple_account_get_int(account, "last_message_timestamp_high", 0);

	if (ia->last_message_timestamp != 0) {
		ia->last_message_timestamp = (ia->last_message_timestamp << 32) | ((guint64) purple_account_get_int(account, "last_message_timestamp_low", 0) & 0xFFFFFFFF);
	}
	
	const gchar *cookies = purple_account_get_string(ia->account, "cookies", NULL);
	if (cookies != NULL) {
		gchar **cookie_pieces = g_strsplit_set(cookies, "=;", -1);
		gint i;
		for (i = 0; cookie_pieces[i] && cookie_pieces[i+1]; i+=2) {
			g_hash_table_replace(ia->cookie_table, g_strdup(cookie_pieces[i]), g_strdup(cookie_pieces[i+1]));
			
			if (purple_strequal(cookie_pieces[i], "csrftoken")) {
				ia->csrftoken = g_strdup(cookie_pieces[i+1]);
			}
		}
		g_strfreev(cookie_pieces);
		
		if (ia->csrftoken) {
			ig_login_successful(ia, NULL, NULL);
			return;
		}
	}
	
	JsonObject *obj = json_object_new();
	gchar *uuid = purple_uuid_random();
	gchar *postdata;
	
	json_object_set_string_member(obj, "_csrftoken", "missing");
	json_object_set_string_member(obj, "device_id", ia->device_id);
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
	
	if (ia->heartbeat_timeout) {
		g_source_remove(ia->heartbeat_timeout);
	}
	
	while (ia->http_conns) {
		purple_http_conn_cancel(ia->http_conns->data);
		ia->http_conns = g_slist_delete_link(ia->http_conns, ia->http_conns);
	}
	
	purple_http_keepalive_pool_unref(ia->keepalive_pool);

	// Save cookies to accounts.xml to login with later
	gchar *cookies = ig_cookies_to_string(ia);
	purple_account_set_string(ia->account, "cookies", cookies);
	g_free(cookies);
	g_hash_table_destroy(ia->cookie_table);
	ia->cookie_table = NULL;
	
	g_free(ia->csrftoken);
	g_free(ia->challenge_url);
	
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
	prpl_info->send_im = ig_send_im;
	// prpl_info->send_typing = instagram_send_typing;
	// prpl_info->join_chat = instagram_join_chat;
	// prpl_info->get_chat_name = instagram_get_chat_name;
	// prpl_info->find_blist_chat = instagram_find_chat;
	// prpl_info->chat_invite = instagram_chat_invite;
	// prpl_info->chat_send = instagram_chat_send;
	// prpl_info->set_chat_topic = instagram_chat_set_topic;
	// prpl_info->get_cb_real_name = instagram_get_real_name;
	prpl_info->add_buddy = ig_add_buddy;
	// prpl_info->remove_buddy = instagram_buddy_remove;
	// prpl_info->group_buddy = instagram_fake_group_buddy;
	// prpl_info->rename_group = instagram_fake_group_rename;
	prpl_info->get_info = ig_get_info;
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