/* FlashShitD - a socket policy file server
 * Copyright 2009 Andrea Marchesini <baku@ippolita.net>
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "flashShit.h"

#include <glib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef G_OS_UNIX
#  include <signal.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <errno.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <grp.h>
#  include <pwd.h>
#endif

static void logging (FlashShit * fs, gboolean verbose, gchar * format, ...);

static gboolean configure (FlashShit * fs, int *argc, char ***argv);
static void configure_free (FlashShit * fs);

static gboolean permission (FlashShit * fs);

static gboolean pidfile (FlashShit * fs);

static gboolean socket_open (FlashShit * fs);
static void socket_close (FlashShit * fs);
static gboolean socket_read (GIOChannel * source, GIOCondition cond,
			     FlashShit * fs);
static gboolean socket_read_timeout (FlashShit * fs);

static gboolean socket_client_read (GIOChannel * source, GIOCondition cond,
				    FlashShitClient * client);
static gboolean socket_client_read_timeout (FlashShitClient * client);
static gboolean socket_client_write (GIOChannel * source, GIOCondition cond,
				     FlashShitClient * client);
static gboolean socket_client_write_timeout (FlashShitClient * client);

static gboolean socket_client_message (FlashShitClient * client);

static gboolean socket_client_timeout (FlashShitClient * client);
static void socket_client_timeout_refresh (FlashShitClient * client);
static void socket_client_close (FlashShitClient * client);

int
main (int argc, char *argv[])
{
  FlashShit fs;

  if (configure (&fs, &argc, &argv) == FALSE)
    return 1;

#ifdef G_OS_UNIX
  if (fs.foreground == FALSE)
    {
      switch (fork ())
	{
	case -1:
	  g_print ("Error forking: %s", g_strerror (errno));
	  return 1;

	case 0:
	  break;

	default:
	  return 0;
	}
    }
#endif

#ifdef G_OS_UNIX
  pidfile (&fs);
#endif

#ifdef G_OS_UNIX
  signal (SIGPIPE, SIG_IGN);
#endif

  logging (&fs, FALSE, PACKAGE " daemon started.");

  if (socket_open (&fs) == FALSE)
    return 1;

#ifdef G_OS_UNIX
  if (permission (&fs) == FALSE)
    return 1;
#endif

  fs.loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (fs.loop);
  g_main_loop_unref (fs.loop);

  logging (&fs, FALSE, PACKAGE " daemon quitting.");

  socket_close (&fs);

  configure_free (&fs);

  return 0;
}

/* LOGGING ******************************************************************/
static void
logging (FlashShit * fs, gboolean verbose, gchar * format, ...)
{
  va_list va;

  va_start (va, format);
  format = g_strdup_vprintf (format, va);
  va_end (va);

  if (verbose == FALSE || fs->verbose == TRUE)
    g_print ("%s\n", format);

  g_free (format);
}

/* CONFIGURATION ************************************************************/
static gboolean
configure (FlashShit * fs, int *argc, char ***argv)
{
  GError *error = NULL;
  GOptionContext *context;

  gchar *policyfile = NULL;

  GOptionEntry entries[] = {
    {"policyfile", 'f', 0, G_OPTION_ARG_STRING, &policyfile, "Policy File", NULL},
    {"interface", 'i', 0, G_OPTION_ARG_STRING, &fs->interface, "Binding interface (default: any)", NULL},
    {"port", 'p', 0, G_OPTION_ARG_INT, &fs->port, "Binding port (default: 843)", NULL},
    {"limit-timeout", 't', 0, G_OPTION_ARG_INT, &fs->limit_timeout, "Limit of seconds per client (default: 10)", NULL},
    {"debug", 'd', 0, G_OPTION_ARG_NONE, &fs->debug, "Be debug", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &fs->verbose, "Be verbose", NULL},

#ifdef G_OS_UNIX
    {"pidfile", 'P', 0, G_OPTION_ARG_STRING, &fs->pidfile, "Save the pid into a file", NULL},
    {"foreground", 'F', 0, G_OPTION_ARG_NONE, &fs->foreground, "Undemonize", NULL},
    {"username", 'u', 0, G_OPTION_ARG_STRING, &fs->username, "Be this user", NULL},
    {"groupname", 'g', 0, G_OPTION_ARG_STRING, &fs->groupname, "Be this group", NULL},
#endif

    {NULL}
  };

  memset (fs, 0, sizeof (FlashShit));

  fs->port = DEFAULT_PORT;
  fs->limit_timeout = DEFAULT_TIMEOUT;

  context = g_option_context_new ("- " PACKAGE " daemon");
  g_option_context_add_main_entries (context, entries, NULL);

  if (g_option_context_parse (context, argc, argv, &error) == FALSE)
    {
      g_print ("Option parsing failed: %s\n", error->message);
      return FALSE;
    }

  g_option_context_free (context);

  if (!policyfile)
    {
      g_print ("Please, set a policy file.\n");
      return FALSE;
    }

  if (g_file_get_contents
      (policyfile, &fs->policy, &fs->policy_length, &error) == FALSE)
    {
      g_print ("Error reading the policy file '%s': %s", policyfile,
	       error->message);
      return FALSE;
    }

  return TRUE;
}

static void
configure_free (FlashShit * fs)
{
  if (fs->interface)
    g_free (fs->interface);

  if (fs->username)
    g_free (fs->username);

  if (fs->groupname)
    g_free (fs->groupname);

  if (fs->policy)
    g_free (fs->policy);
}

/* PERMISSION ***************************************************************/
#ifdef G_OS_UNIX
static gboolean
permission (FlashShit * fs)
{
  if (fs->groupname)
    {
      struct group *gr;

      if (!(gr = getgrnam (fs->groupname)) || setgid (gr->gr_gid))
	{
	  g_print ("Error setting the GROUP permission of '%s'",
		   fs->groupname);

	  return FALSE;
	}
    }

  if (fs->username)
    {
      struct passwd *pw;

      if (!(pw = getpwnam (fs->username)) || setuid (pw->pw_uid))
	{
	  g_print ("Error setting the USER permission of '%s'", fs->username);

	  return FALSE;
	}
    }

  return TRUE;
}
#endif

/* PIDFILE ******************************************************************/
#ifdef G_OS_UNIX
static gboolean
pidfile (FlashShit * fs)
{
  GError *error = NULL;

  if (fs->pidfile)
    {
      gchar buffer[1024];

      g_snprintf (buffer, sizeof (buffer), "%d", getpid ());

      if (g_file_set_contents (fs->pidfile, buffer, -1, &error) == FALSE)
	{
	  g_print ("Error saving the pidfile '%s': %s", fs->pidfile,
		   error->message);

	  return FALSE;
	}
    }

  return TRUE;
}
#endif

/* MAIN SOCKET **************************************************************/
static gboolean
socket_open (FlashShit * fs)
{
  gint fd, yes = 1;
  struct sockaddr_in sock;
  GIOChannel *channel;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      g_print ("Error creating the socket: %s", g_strerror (errno));
      return FALSE;
    }

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int)))
    {
      close (fd);
      g_print ("Error setting options on the socket: %s\n",
	       g_strerror (errno));
      return FALSE;
    }

  memset (&sock, 0, sizeof (struct sockaddr_in));
  sock.sin_family = AF_INET;
  sock.sin_port = htons (fs->port ? fs->port : DEFAULT_PORT);

  if (!fs->interface)
    sock.sin_addr.s_addr = htonl (INADDR_ANY);

  else
    {
      struct hostent *hp;

      if (!(hp = gethostbyname (fs->interface)))
	{
	  close (fd);
	  g_print ("Error resolving the interface '%s': %s", fs->interface,
		   g_strerror (errno));
	  return FALSE;
	}

      sock.sin_family = hp->h_addrtype;
      memcpy (&sock.sin_addr, hp->h_addr, hp->h_length);
    }

  if (bind (fd, (struct sockaddr *) &sock, sizeof (struct sockaddr_in)) < 0)
    {
      close (fd);
      g_print ("Error binding the socket: %s\n", g_strerror (errno));
      return FALSE;
    }

  if (listen (fd, DEFAULT_BACKLOG) < 0)
    {
      close (fd);
      g_print ("Error listeining on the socket: %s\n", g_strerror (errno));
      return FALSE;
    }

  logging (fs, TRUE, "Socket opened (interface: %s, port: %d)", fs->interface,
	   fs->port);

#ifdef G_OS_WIN32
  channel = g_io_channel_win32_new_fd (fd);
#else
  channel = g_io_channel_unix_new (fd);
#endif

  fs->iosocket = channel;
  fs->iosocket_fd = fd;

  g_io_channel_set_encoding (channel, NULL, NULL);

  fs->iosocket_source = g_io_create_watch (fs->iosocket, G_IO_IN);
  g_source_set_callback (fs->iosocket_source, (GSourceFunc) socket_read, fs,
			 NULL);
  g_source_attach (fs->iosocket_source, g_main_context_default ());

  return TRUE;
}

static void
socket_close (FlashShit * fs)
{
  logging (fs, TRUE, "Socket closing...");

  g_source_destroy (fs->iosocket_source);
  g_source_unref (fs->iosocket_source);

  g_io_channel_shutdown (fs->iosocket, FALSE, NULL);
  g_io_channel_unref (fs->iosocket);
}

static gboolean
socket_read (GIOChannel * source, GIOCondition cond, FlashShit * fs)
{
  struct sockaddr_in sock;

  FlashShitClient *client;

  gchar *ip;
  gint fd;

  socklen_t size = sizeof (struct sockaddr_in);
  gint addr;

  /* IPv4 accept: */
  if ((fd = accept (fs->iosocket_fd, (struct sockaddr *) &sock, &size)) < 0)
    {
      g_source_destroy (fs->iosocket_source);
      g_source_unref (fs->iosocket_source);

      fs->iosocket_source = g_timeout_source_new (200);
      g_source_set_callback (fs->iosocket_source,
			     (GSourceFunc) socket_read_timeout, fs, NULL);
      g_source_attach (fs->iosocket_source, g_main_context_default ());

      return FALSE;
    }

  addr = ntohl (sock.sin_addr.s_addr);

  ip =
    g_strdup_printf ("%d.%d.%d.%d", (unsigned int) addr >> 24,
		     (unsigned int) (addr >> 16) % 256,
		     (unsigned int) (addr >> 8) % 256,
		     (unsigned int) addr % 256);

  /* A new struct for a new client: */
  client = g_malloc0 (sizeof (FlashShitClient));
  client->fs = fs;

  logging (fs, TRUE, "New connection %p (%s).", client, ip);

  client->ip = ip;

#ifdef G_OS_WIN32
  client->channel = g_io_channel_win32_new (fd);
#else
  client->channel = g_io_channel_unix_new (fd);
#endif
  g_io_channel_set_encoding (client->channel, NULL, NULL);
  g_io_channel_set_flags (client->channel,
			  g_io_channel_get_flags (client->
						  channel) |
			  G_IO_FLAG_NONBLOCK, NULL);

  client->channel_source = g_io_create_watch (client->channel, G_IO_IN);
  g_source_set_callback (client->channel_source,
			 (GSourceFunc) socket_client_read, client, NULL);
  g_source_attach (client->channel_source, g_main_context_default ());

  /* A timer for idle connections: */
  socket_client_timeout_refresh (client);

  fs->clients = g_list_prepend (fs->clients, client);
  return TRUE;
}

static gboolean
socket_read_timeout (FlashShit * fs)
{
  g_source_destroy (fs->iosocket_source);
  g_source_unref (fs->iosocket_source);

  fs->iosocket_source = g_io_create_watch (fs->iosocket, G_IO_IN);
  g_source_set_callback (fs->iosocket_source, (GSourceFunc) socket_read, fs,
			 NULL);
  g_source_attach (fs->iosocket_source, g_main_context_default ());

  return FALSE;
}

/* CLIENT *******************************************************************/

/* This function reads something from the client: */
static gboolean
socket_client_read (GIOChannel * source, GIOCondition cond,
		    FlashShitClient * client)
{
  gsize done;
  GIOStatus status;

  status =
    g_io_channel_read_chars (source, client->body + client->body_done,
			     sizeof (client->body) - client->body_done, &done,
			     NULL);

  /* The status of the read: */
  switch (status)
    {
    case G_IO_STATUS_NORMAL:
      break;

      /* Setting a delay: */
    case G_IO_STATUS_AGAIN:
      g_source_destroy (client->channel_source);
      g_source_unref (client->channel_source);

      client->channel_source = g_timeout_source_new (200);
      g_source_set_callback (client->channel_source,
			     (GSourceFunc) socket_client_read_timeout, client,
			     NULL);
      g_source_attach (client->channel_source, g_main_context_default ());
      return FALSE;

      /* Close the socket: */
    case G_IO_STATUS_ERROR:
    case G_IO_STATUS_EOF:
      socket_client_close (client);
      return FALSE;
    }

  /* Removing the timeout: */
  socket_client_timeout_refresh (client);

  client->body_done += done;

  /* Too many characters: */
  if (client->body_done >= sizeof (client->body))
    {
      socket_client_close (client);
      return FALSE;
    }

  if (client->fs->debug == TRUE && !strncmp (client->body, "quit", 4))
    {
      logging (client->fs, FALSE, "Closing by a client request.");

      g_main_loop_quit (client->fs->loop);
      socket_client_close (client);
      return FALSE;
    }

  switch (socket_client_message (client))
    {
      /* not yet: */
    case -1:
      return TRUE;

      /* ok: */
    case 0:
      logging (client->fs, TRUE, "Valid request from client %p.", client);

      g_source_destroy (client->channel_source);
      g_source_unref (client->channel_source);

      client->channel_source = g_io_create_watch (client->channel, G_IO_OUT);
      g_source_set_callback (client->channel_source,
			     (GSourceFunc) socket_client_write, client, NULL);
      g_source_attach (client->channel_source, g_main_context_default ());

      return FALSE;

      /* error: */
    case 1:
      logging (client->fs, TRUE, "Invalid request from client %p.", client);

      socket_client_close (client);
      return FALSE;

    default:
      return FALSE;
    }
}

static gboolean
socket_client_message (FlashShitClient * client)
{
  gint i;

  /* removing spaces... */
  for (i = 0; i < client->body_done; i++)
    if (client->body[i] != ' ' && client->body[i] != '\t'
	&& client->body[i] != '\n')
      break;

  if (i == client->body_done)
    return -1;

  /* checking the size of the message: */
  if ((client->body_done - i) < DEFAULT_MSG_LENGTH)
    return -1;

  /* comparing the string: */
  if (strncmp (client->body + i, DEFAULT_MSG, DEFAULT_MSG_LENGTH))
    return 1;

  /* removing spaces: */
  for (i += DEFAULT_MSG_LENGTH; i < client->body_done; i++)
    if (client->body[i] != ' ' && client->body[i] != '\t'
	&& client->body[i] != '\n')
      break;

  if (i > client->body_done - 3)
    return -1;

  /* searching '/>': */
  if (client->body[i] != '/' || client->body[i + 1] != '>'
      || client->body[i + 2] != '\0')
    return 1;

  return 0;
}

static gboolean
socket_client_read_timeout (FlashShitClient * client)
{
  g_source_destroy (client->channel_source);
  g_source_unref (client->channel_source);

  client->channel_source = g_io_create_watch (client->channel, G_IO_IN);
  g_source_set_callback (client->channel_source,
			 (GSourceFunc) socket_client_read, client, NULL);
  g_source_attach (client->channel_source, g_main_context_default ());
  return FALSE;
}

static gboolean
socket_client_write (GIOChannel * source, GIOCondition cond,
		     FlashShitClient * client)
{
  gsize done;
  GIOStatus status;

  if ((status =
       g_io_channel_write_chars (source,
				 client->fs->policy + client->policy_done,
				 client->fs->policy_length -
				 client->policy_done, &done,
				 NULL)) == G_IO_STATUS_NORMAL)
    status = g_io_channel_flush (client->channel, NULL);

  /* The status of the read: */
  switch (status)
    {
    case G_IO_STATUS_NORMAL:
      client->policy_done += done;

      if (client->policy_done >= client->fs->policy_length)
	{
	  logging (client->fs, TRUE, "Written policy to client %p.", client);
	  socket_client_close (client);
	  return FALSE;
	}

      break;

      /* Setting a delay: */
    case G_IO_STATUS_AGAIN:
      g_source_destroy (client->channel_source);
      g_source_unref (client->channel_source);

      client->channel_source = g_timeout_source_new (200);
      g_source_set_callback (client->channel_source,
			     (GSourceFunc) socket_client_write_timeout,
			     client, NULL);
      g_source_attach (client->channel_source, g_main_context_default ());
      return FALSE;

      /* Close the socket: */
    case G_IO_STATUS_ERROR:
    case G_IO_STATUS_EOF:
      socket_client_close (client);
      return FALSE;
    }

  /* Removing the timeout: */
  socket_client_timeout_refresh (client);

  return TRUE;
}

static gboolean
socket_client_write_timeout (FlashShitClient * client)
{
  g_source_destroy (client->channel_source);
  g_source_unref (client->channel_source);

  client->channel_source = g_io_create_watch (client->channel, G_IO_OUT);
  g_source_set_callback (client->channel_source,
			 (GSourceFunc) socket_client_write, client, NULL);
  g_source_attach (client->channel_source, g_main_context_default ());
  return FALSE;
}

static gboolean
socket_client_timeout (FlashShitClient * client)
{
  logging (client->fs, TRUE, "Removed client %p for timeout.", client);
  socket_client_close (client);
  return FALSE;
}

static void
socket_client_timeout_refresh (FlashShitClient * client)
{
  /* Removing the timeout: */
  if (client->timeout_source)
    {
      g_source_destroy (client->timeout_source);
      g_source_unref (client->timeout_source);
    }

  /* A new timeout: */
  client->timeout_source =
    g_timeout_source_new (client->fs->limit_timeout * 1000);
  g_source_set_callback (client->timeout_source,
			 (GSourceFunc) socket_client_timeout, client, NULL);
  g_source_attach (client->timeout_source, g_main_context_default ());
}

static void
socket_client_close (FlashShitClient * client)
{
  logging (client->fs, TRUE, "Killed client %p.", client);

  client->fs->clients = g_list_remove (client->fs->clients, client);

  if (client->ip)
    g_free (client->ip);

  if (client->channel)
    {
      g_io_channel_shutdown (client->channel, FALSE, NULL);
      g_io_channel_unref (client->channel);
    }

  if (client->channel_source)
    {
      g_source_destroy (client->channel_source);
      g_source_unref (client->channel_source);
    }

  if (client->timeout_source)
    {
      g_source_destroy (client->timeout_source);
      g_source_unref (client->timeout_source);
    }

  g_free (client);
}

/* EOF */
