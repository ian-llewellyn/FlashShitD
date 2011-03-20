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

#include <glib.h>

#define DEFAULT_BACKLOG		5
#define DEFAULT_PORT		843
#define DEFAULT_TIMEOUT		10
#define DEFAULT_BODY_LENGTH	512

#define DEFAULT_MSG		"<policy-file-request"
#define DEFAULT_MSG_LENGTH	20

typedef struct flashShit_t FlashShit;

struct flashShit_t
{
  gchar *	interface;
  gint		port;
  gboolean	debug;
  gboolean	verbose;
  gboolean	foreground;
  gchar *	pidfile;

  gchar *	username;
  gchar *	groupname;

  guint		limit_timeout;

  gchar *	policy;
  gsize		policy_length;

  GMainLoop *	loop;

  GIOChannel *	iosocket;
  gint		iosocket_fd;
  GSource *	iosocket_source;

  GList *	clients;
};

typedef struct flashShitClient_t FlashShitClient;

struct flashShitClient_t
{
  FlashShit *	fs;

  gchar *	ip;

  GIOChannel *	channel;
  GSource *	channel_source;

  GSource *	timeout_source;

  gchar		body[DEFAULT_BODY_LENGTH];
  guint		body_done;

  guint		policy_done;
};

/* EOF */
