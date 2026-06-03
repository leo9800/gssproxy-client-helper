#define _GNU_SOURCE
#include <errno.h>
#include <krb5/krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <termios.h>

#ifndef GSSPROXY_CLIENTS_PATH
#define GSSPROXY_CLIENTS_PATH "/var/lib/gssproxy/clients"
#endif
#define ARRLEN(x) (sizeof(x) / sizeof((x)[0]))
#define safe_free(x) if(x != NULL) {free(x); x = NULL;}
#define checkret(x) do {krb5_error_code ret = (x); if(ret) {com_err(#x, ret, NULL); exit(EXIT_FAILURE);}} while (0)


static inline void keytab_paths(uid_t uid, char **old, char **new, char **krb5);
static inline char *read_password(const char *name);
static inline void remove_keytab_ccache(uid_t uid);
static inline krb5_keytab_entry *create_keytab_entry(
	krb5_context context,
	krb5_kvno kvno,
	krb5_enctype enctype,
	krb5_principal principal,
	krb5_data password
);

int main(int argc, char const *argv[])
{
	uid_t uid;
	struct passwd *pwd;
	char *pwbuf = NULL;
	char *old_ktpath, *new_ktpath, *krb5_ktpath;
	char *raw_principal;
	krb5_error_code ret;
	krb5_data password;
	krb5_context context;
	krb5_keytab keytab;
	krb5_principal principal;
	krb5_kvno kvno;
	krb5_keytab_entry *entry;
	krb5_enctype enctypes[] = {
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		ENCTYPE_AES128_CTS_HMAC_SHA1_96
	};

	if (argc != 2 || (strcmp(argv[1], "load") && strcmp(argv[1], "unload"))) {
		fprintf(stderr, "Usage: %s <load | unload>\n", argv[0]);
		return EXIT_FAILURE;
	}

	uid = getuid();
	pwd = getpwuid(uid);
	if (pwd == NULL) return EXIT_FAILURE;

	if (!strcmp(argv[1], "unload")) {
		remove_keytab_ccache(uid);
		return EXIT_SUCCESS;
	}

	pwbuf = read_password(pwd->pw_name);
	keytab_paths(uid, &old_ktpath, &new_ktpath, &krb5_ktpath);

	kvno = 1;
	password.data = pwbuf;
	password.length = strlen(password.data);

	checkret(krb5_init_context(&context));
	checkret(krb5_kt_resolve(context, krb5_ktpath, &keytab));
	checkret(krb5_parse_name(context, pwd->pw_name, &principal));
	checkret(krb5_unparse_name(context, principal, &raw_principal));
	krb5_free_principal(context, principal);
	checkret(krb5_parse_name(context, raw_principal, &principal));

	for (int i = 0; i < ARRLEN(enctypes); i++) {
		entry = create_keytab_entry(context, kvno++, enctypes[i], principal, password);
		checkret(krb5_kt_add_entry(context, keytab, entry));
		krb5_copy_principal(context, principal, &principal);
		krb5_free_keytab_entry_contents(context, entry);
		safe_free(entry);
	}

	krb5_kt_close(context, keytab);
	krb5_free_principal(context, principal);
	krb5_free_data_contents(context, &password);
	krb5_free_context(context);
	remove_keytab_ccache(uid);
	if (rename(new_ktpath, old_ktpath) != 0) {
		perror("rename");
		exit(EXIT_FAILURE);
	}
	safe_free(raw_principal);
	safe_free(new_ktpath);
	safe_free(old_ktpath);
	safe_free(krb5_ktpath);
	return EXIT_SUCCESS;
}

static inline char *read_password(const char *name)
{
	struct termios tflags;
	char *buf = NULL;
	size_t size;
	int ret;

	printf("Please input Kerberos password for %s: ", name);
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &tflags);
	tflags.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tflags);
	ret = getline(&buf, &size, stdin);
	tflags.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tflags);
	printf("\n");
	if (ret == -1 || buf == NULL) {
		perror("getline");
		exit(EXIT_FAILURE);
	}
	buf[strcspn(buf, "\n")] = '\0';
	return buf;
}

static inline void keytab_paths(uid_t uid, char **old, char **new, char **krb5)
{
	if (asprintf(old,         GSSPROXY_CLIENTS_PATH"/%d.keytab",     uid) < 0) exit(EXIT_FAILURE);
	if (asprintf(new,         GSSPROXY_CLIENTS_PATH"/%d.keytab.new", uid) < 0) exit(EXIT_FAILURE);
	if (asprintf(krb5, "FILE:"GSSPROXY_CLIENTS_PATH"/%d.keytab.new", uid) < 0) exit(EXIT_FAILURE);
}

static inline void remove_keytab_ccache(uid_t uid)
{
	char *keytab_path;
	char *ccache_path;

	if (asprintf(&keytab_path, GSSPROXY_CLIENTS_PATH"/%d.keytab", uid) < 0) exit(EXIT_FAILURE);
	if (asprintf(&ccache_path, GSSPROXY_CLIENTS_PATH"/krb5cc_%d", uid) < 0) exit(EXIT_FAILURE);
	if (remove(keytab_path) != 0 && errno != ENOENT) exit(EXIT_FAILURE);
	if (remove(ccache_path) != 0 && errno != ENOENT) exit(EXIT_FAILURE);
	safe_free(keytab_path);
	safe_free(ccache_path);
}

static inline krb5_keytab_entry *create_keytab_entry(
	krb5_context context,
	krb5_kvno kvno,
	krb5_enctype enctype,
	krb5_principal principal,
	krb5_data password
)
{
	krb5_keytab_entry *entry = malloc(sizeof(krb5_keytab_entry));
	krb5_data salt;
	krb5_keyblock key;

	if (!entry) exit(EXIT_FAILURE);
	memset(entry, 0, sizeof(krb5_keytab_entry));
	entry->principal = principal;
	entry->vno = kvno;
	entry->key.enctype = enctype;

	checkret(krb5_c_keylengths(context, entry->key.enctype, NULL, (size_t *) &entry->key.length));
	checkret(krb5_principal2salt(context, principal, &salt));
	checkret(krb5_c_string_to_key(context, entry->key.enctype, &password, &salt, &key));

	entry->key.contents = key.contents;
	krb5_free_data_contents(context, &salt);
	return entry;
}