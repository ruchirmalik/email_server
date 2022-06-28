#include "mailuser.h"
#include "netbuffer.h"
#include "server.h"
#include "mailuser.h"
#include "netbuffer.h"
#include "server.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdbool.h> //bool type won't work without this aghhhhhhhhhhhh

//important constants that will be frequently used in the program
#define NULL_CHAR '\0'
#define NULL_STR ""
#define SPACE " "

#define DEBUG 1
#define APP_NAME "POP3 Server"
#define APP_VER "10" 
#define MAX_ARG_LENGTH 40
#define MAX_LINE_LENGTH 512

//Constants for Replies
#define OK "+OK\r\n"
#define BAD_SEQUENCE "-ERR Bad command sequence.\r\n"
#define SYNTAX_ERROR "-ERR Syntax error.\r\n"


//MAILBOX SESSION
struct mail_session 
{
  mail_list_t mails;
  net_buffer_t nb;
  char recvbuf[MAX_LINE_LENGTH + 1];
  char sendbuf[MAX_LINE_LENGTH + 1];
  char user[MAX_ARG_LENGTH + 1];
  int fd;

  bool active;
  bool authenticated;
  bool online;
};


int mail_scan(struct mail_session *session) {
#ifdef DEBUG
  puts("listening...");
#endif
  int out = nb_read_line(session->nb, session->recvbuf);
#ifdef DEBUG
  if (out > 0)
    printf("> %s\n", session->recvbuf);
  else
    printf("mail_scan: %d\n", out);
#endif
  session->active = out > 0;
  return out;
}


int mail_send(struct mail_session *session) {
  int out = send_all(session->fd, session->sendbuf, strlen(session->sendbuf));
#ifdef DEBUG
  if (out > 0)
    printf("< %s\n", session->sendbuf);
  else
    printf("mail_send: %d\n", out);
#endif
  session->active = out > 0;
  return out;
}

// Initializes the session. THIS IS NOT AUTHORIZATION!!!
void initialize_session(struct mail_session *session, int fd)
 {
  session->active = true;
  session->authenticated = false;
  session->fd = fd;
  session->mails = NULL;
  session->nb = nb_create(fd, MAX_LINE_LENGTH);
  session->online = true;
  sprintf(session->sendbuf, "+OK %s %s Ready.\r\n", APP_NAME, APP_VER);
  mail_send(session);
}


bool trim(char *string)
{
  for (long unsigned int i = 0; string[i] != NULL_CHAR; i++)
    if (string[i] == '\r' || string[i] == '\n') {
      string[i] = NULL_CHAR;
#ifdef DEBUG
      printf("trim: %lu\n", i);
#endif
      return true;
    }
  return false;
}


bool copy_response(struct mail_session *session, bool flag, char *response) 
{
  if (flag == false)
    strcpy(session->sendbuf, response);
  return !flag;
}


bool check_arg_len(struct mail_session *session, char *arg)
 {
  return copy_response(session, strlen(arg) <= MAX_ARG_LENGTH, "-ERR Argument overflow.\r\n"
  );
}


bool session_authenticated(struct mail_session *session) {
  return copy_response(session, session->authenticated, BAD_SEQUENCE);
}


bool session_user(struct mail_session *session) {
  return copy_response(session, session->user[0] != '\0', BAD_SEQUENCE);
}


bool session_not_authenticated(struct mail_session *session) {
  return copy_response(session, !session->authenticated, BAD_SEQUENCE);
}


bool pointer_not_null(struct mail_session *session, void *pointer) {
  return copy_response(session, pointer != NULL, SYNTAX_ERROR);
}

//***************************************

// Handles the USER command.
void USER(struct mail_session *session) {
  if (session_not_authenticated(session))
    return;
  char *token = strtok(NULL, SPACE);
  if (pointer_not_null(session, token) || check_arg_len(session, token))
    return;
  if (is_valid_user(token, NULL) == 0) //condition to check if user is valid
  {
    strcpy(session->sendbuf, "-ERR user mismatched.\r\n"); //not valid
    return; 
  }
  strcpy(session->user, token);
  strcpy(session->sendbuf, OK);
}

//PASS Command handler
void PASS(struct mail_session *session)
 {
  if (session_user(session) || session_not_authenticated(session)|| copy_response(session, strlen(session->recvbuf) > 5, SYNTAX_ERROR))
    return;

  char *token = &session->recvbuf[5];

  if (pointer_not_null(session, token) || check_arg_len(session, token))
    return;

  session->authenticated = is_valid_user(session->user, token) != 0;

  for (int i = 0; i < MAX_LINE_LENGTH + 1; i++)
    session->recvbuf[i] = '\0';
  if (session->authenticated) 
  {
    session->mails = load_user_mail(session->user);
    strcpy(session->sendbuf, OK);
  } 
  else {
    strcpy(session->user, NULL_STR);
    strcpy(session->sendbuf, "-ERR pass mismatched.\r\n");
  }
}


void STAT(struct mail_session *session) {
  if (session_authenticated(session))
    return;
  sprintf(session->sendbuf, "+OK %u %lu\r\n",
    get_mail_count(session->mails, 0),
    get_mail_list_size(session->mails)
  );
}


mail_item_t ret_mail(struct mail_session *session, char *arg) 
{
  if (check_arg_len(session, arg))
    return NULL;
  long number = strtol(arg, NULL, 10);
  if (number <= 0) 
  {
    strcpy(session->sendbuf, "-ERR Bad message number.\r\n");
    return NULL;
  }
  mail_item_t out = get_mail_item(session->mails, number - 1);
  if (out == NULL)
    strcpy(session->sendbuf, "-ERR Not found.\r\n");
  return out;
}

//reading mail from the mailbox
mail_item_t parseMail(struct mail_session *session)
 {
  if (session_authenticated(session))
    return NULL;
  char *token = strtok(NULL, SPACE);
  if (pointer_not_null(session, token))
    return NULL;
  return ret_mail(session, token);
}


void LIST(struct mail_session *session) 
{
  if (session_authenticated(session)) //checking if the session is authenticated 
    return; 

  mail_item_t mail;
  char *token = strtok(NULL, SPACE);
  if (token != NULL) {
    mail = ret_mail(session, token);
    if (mail == NULL)
      return;
    sprintf(session->sendbuf, "+OK %s %lu\r\n", token, get_mail_item_size(mail));
  }
   else 
   {
    sprintf(session->sendbuf, "+OK %u messages (%lu octets)\r\n",
      get_mail_count(session->mails, 0),
      get_mail_list_size(session->mails)
    );
    if (mail_send(session) <= 0)
      return;
    unsigned int count = get_mail_count(session->mails, 1);
    for (unsigned int number = 1; number <= count; number++) {
      mail = get_mail_item(session->mails, number - 1);
      if (mail == NULL)
        continue;
      sprintf(session->sendbuf, "%u %lu\r\n",
        number,
        get_mail_item_size(mail)
      );
      if (mail_send(session) <= 0)
        return;
    }
    strcpy(session->sendbuf, ".\r\n");
  }
}


int FLUSHRETR(struct mail_session *session, unsigned long *length, bool *line_ending, FILE *file) 
{
  if (session->sendbuf[0] == '.') 
  {
  
    for (int i = 0; i + 1 < *length; i ++)
      session->sendbuf[i + 1] = session->sendbuf[i];
    session->sendbuf[0] = '.';
  }
  int out = mail_send(session);
  if (out > 0) {
    strcpy(session->sendbuf, NULL_STR);
    *length = 0;
    *line_ending = false;
  } else {
    fclose(file);
  }
  return out;
}


void RETR(struct mail_session *session) 
{
  mail_item_t mail = parseMail(session);
  if (mail == NULL)
    return;
  unsigned long length = 0;
  bool line_ending = false;
  FILE *file = get_mail_item_contents(mail);
  if (file == NULL) {
    strcpy(session->sendbuf, "-ERR Bad mail file.\r\n");
    return;
  }
  strcpy(session->sendbuf, OK);
  if (FLUSHRETR(session, &length, &line_ending, file) <= 0)
    return;
  for (int character = getc(file); character != EOF; character = getc(file)) {
    session->sendbuf[length++] = character;
    session->sendbuf[length] = '\0';
    if (length >= MAX_LINE_LENGTH - 2) {
      strcat(session->sendbuf, "\r\n");
    } else if (!line_ending || character != '\n') {
      line_ending = character == '\r';
      continue;
    }
    // Only the first conditional and the inverse of the second reach here.
    if (FLUSHRETR(session, &length, &line_ending, file) <= 0)
      return;
  }
  if (length > 0 && FLUSHRETR(session, &length, &line_ending, file) <= 0)
    return;
  fclose(file);
  strcpy(session->sendbuf, ".\r\n");
}


void DELE(struct mail_session *session) 
{
  mail_item_t mail = parseMail(session);
  if (mail == NULL)
    return;
  mark_mail_item_deleted(mail);
  strcpy(session->sendbuf, OK);
}


void RSET(struct mail_session *session)
 {
  if (session_authenticated(session))
    return;
  unsigned int count = reset_mail_list_deleted_flag(session->mails);
  sprintf(session->sendbuf, "+OK %u messages restored\r\n", count);
}


void NOOP(struct mail_session *session) 
{
  if (session_authenticated(session))
    return;
  strcpy(session->sendbuf, OK);
}


void QUIT(struct mail_session *session) 
{
  session->online = false;
  sprintf(session->sendbuf, "+OK %s %s End.\r\n", APP_NAME, APP_VER);
}


void do_dc2s(struct mail_session *session) {
  puts("  recvbuf:");
  printf("%s\n  :recvbuf\n", session->recvbuf);
  puts("  sendbuf:");
  printf("%s\n  :sendbuf\n", session->sendbuf);
  puts("  user:");
  printf("%s\n  :user\n", session->user);
  puts("  fd:");
  printf("%u\n  :fd\n", session->fd);
  puts("active\tauthenticated\tonline:");
  printf("%u\t%u\t%u\n:active\tauthenticated\tonline\n",
    session->active, session->authenticated, session->online
  );
  sprintf(session->sendbuf, "+OK %s %s DEBUG.\r\n", APP_NAME, APP_VER);
}

//********** 
void handle_client(int fd)
 {
  struct mail_session *session = malloc(sizeof(struct mail_session));

  char workbuf[MAX_LINE_LENGTH + 1];
  char *token;

  //INITIALIZING SESSION
  initialize_session(session, fd);

//as long as session is active, the loop goes on
  while (session->active && session->online) 
  {
    if (mail_scan(session) <= 0)
      break;

    if (strncmp(session->recvbuf, "\r\n", 2) == 0)
      continue;

    if (!trim(session->recvbuf)) 
    {
      strcpy(session->sendbuf, "-ERR Command too long.\r\n");
    } 
    else 
    {
      strcpy(workbuf, session->recvbuf);
      token = strtok(workbuf, SPACE);

      if (strcasecmp(token, "USER") == 0)
        USER(session);
      else if (strcasecmp(token, "PASS") == 0)
        PASS(session);
      else if (strcasecmp(token, "STAT") == 0)
        STAT(session);
      else if (strcasecmp(token, "LIST") == 0)
        LIST(session);
      else if (strcasecmp(token, "RETR") == 0)
        RETR(session);
      else if (strcasecmp(token, "DELE") == 0)
        DELE(session);
      else if (strcasecmp(token, "RSET") == 0)
        RSET(session);
      else if (strcasecmp(token, "NOOP") == 0)
        NOOP(session);
      else if (strcasecmp(token, "QUIT") == 0)
        QUIT(session);
#ifdef DEBUG
      else if (strcasecmp(token, "dc2s") == 0)
        do_dc2s(session);
#endif
      else
        strcpy(session->sendbuf, "-ERR Command not recognized.\r\n");
    }
    if (!session->active || mail_send(session) <= 0)
      break;
  }
  destroy_mail_list(session->mails);
  nb_destroy(session->nb);
  free(session);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    return 1;
  }
  run_server(argv[1], handle_client);
  return 0;
}

