# GSSProxy Client Helper

This utility allows unprivileged users to load or unload Kerberos keytab with their hashed password to GSSProxy without requiring root access.

By invoking `gssproxy-keytab load` and entering correct Kerberos password when prompted the keytab is loaded to GSSProxy.

By invoking `gssproxy-keytab unload` the keytab is removed from GSSProxy.

This ulitity may help those who run long-lasting computing jobs on clusters where jobs consume data resides on kerberized NFS and the access is required to be presist longer than the (renewable) lifetime of KRBTGT.

With the help of GSSProxy (and envvar `GSS_USE_PROXY=yes` set for `rpc.gssd`) computing jobs run on behave of users could presist access to kerberized NFS mounts without recurringly invocation of `kinit` before the expiration of KRBTGT.

## Build & Install

```sh
gcc -s -o gssproxy-keytab main.c $(pkg-config --libs krb5)
install -o root -g root -m 6755 gssproxy-keytab /usr/local/bin
```

alternatively, if the *clients* directory of GSSProxy is not `/var/lib/gssproxy/clients`:

```sh
gcc -s -o gssproxy-keytab main.c $(pkg-config --libs krb5) -DGSSPROXY_CLIENTS_PATH=\"/usr/local/var/lib/gssproxy/clients\"
install -o root -g root -m 6755 gssproxy-keytab /usr/local/bin
```

## Todos

 - This utility is not guaranteed to be memory safe, memory leaks are expected but it won't be error-prone as it is designed to be one-shot than long-running daemon.
 - TODO: check users' password by initiating Kerberos negotiation (get TGT, then get ST of host) against host keytab, prompting users for wrong password.
