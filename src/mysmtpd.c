#include "netbuffer.h"
#include "mailuser.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 1024
#define MAX_DATA_SIZE 65536
#define MAX_PATH_LENGTH 256
#define DEBUG 1

//defining constants for reply codes in numeric order
#define OK "250 Completed\r\n"
#define OK_354 "354 OK Start mail input\r\n"
#define SERVICE_NOT_AVAILABLE "421 Service not available, closing channel\r\n"
#define LOCAL_ERROR "451 Requested action aborted due to local error\r\n"
#define SYNTAX_ERROR "500 Syntax error, command unrecognized or command too long\r\n"
#define SYNTAX_ERROR_PARAM "501 Syntax error in parameters or arguments\r\n"
#define NOT_IMPLEMENTED "502 Command not implemented\r\n"
#define BAD_SEQUENCE "503 Bad sequence of commands\r\n"
#define MAILBOX_UNAVAILABLE "550 mailbox unavailable\r\n"
#define EXCEEDED_STORAGE_ALLOCATION "552 Requested mail action aborted\r\n"

#define TRANS_FAILED "554 transaction failed"
#define PARA_NOT_RECOGNISED "555 parameters not recognized or not implemented\r\n"sc
#define SEND_STRING_ERROR "Cannot send string to client.\n"

#define NULL_STR ""
#define NULL_CHAR '\0'
#define SPACE " "

#define APP_NAME "SMTP Server"
#define APP_VER "10.0"

struct mail_session
{
  struct utsname *uname;
  net_buffer_t nb;
  user_list_t users;

  char reverse_path[MAX_PATH_LENGTH + 1];
  char recvbuf[MAX_LINE_LENGTH + 1];
  char sendbuf[MAX_LINE_LENGTH + 1];

  int fd;

  bool online;
  bool active;
  bool heloed;
  bool mailed;
  
};

//*******************


int mail_scan(struct mail_session *session)
{
#ifdef DEBUG
  puts("listening...");
#endif
  int out = nb_read_line(session->nb, session->recvbuf);
#ifdef DEBUG
  if (out > 0)
    printf("> %s\n", session->recvbuf);
  else
    printf("nm_scan: %d\n", out);
#endif
  session->active = out > 0;
  return out;
}



int mail_send(struct mail_session *session)
{
  int out = send_all(session->fd, session->sendbuf, strlen(session->sendbuf));
#ifdef DEBUG
  if (out > 0)
    printf("< %s\n", session->sendbuf);
  else
    printf("nm_send: %d\n", out);
#endif
  session->active = out > 0;
  return out;
}

//**********************

//helper function
void initialize_buffers(struct mail_session *session)
{
  strcpy(session->reverse_path, NULL_STR);
  destroy_user_list(session->users); //deletes the old user list
  session->users = create_user_list(); //creates a new user list
}

//helper function
void initialize_states(struct mail_session *session)
{
  session->mailed = false;
}



//SESSION INITIATION
void initialize_session(struct mail_session *session, int fd, struct utsname *uname)
{
  session->active = true;
  session->online = true;
  session->fd = fd;
  session->heloed = false;
  session->nb = nb_create(fd, MAX_LINE_LENGTH);
  session->uname = uname;
  session->users = NULL;
  
  //initializing buffers and states by calling their helper functions
  initialize_buffers(session);
  initialize_states(session);

  sprintf(session->sendbuf, "220 %s %s %s\r\n", session->uname->nodename, APP_NAME, APP_VER);
  mail_send(session);
}

bool trim(char *str) 
{ 
  //iterating through to the end of the string
  for (long unsigned int i = 0; str[i] != NULL_CHAR; i++)
    if (str[i] == '\n' || str[i] == '\r')
     {
      str[i] = NULL_CHAR;
#ifdef DEBUG
      printf("trim: %lu\n", i);
#endif
      return true;
    }
  return false;
}


//******************


void mail_write(struct mail_session *session, char *data, size_t size) 
{
  char filename[strlen("MAIL") + 7];
  sprintf(filename, "%sXXXXXX", APP_NAME);
  int fd = mkstemp(filename);
  write(fd, data, size);
  close(fd);
  save_user_mail(filename, session->users);
  remove(filename);
}

//copies response into session->sendbuf if the flag is false. Doesn't do anything if flag is true
bool copy_response(struct mail_session *session, bool flag, char *response)
 {
  if (flag == false)
    strcpy(session->sendbuf, response);
  return !flag;
}

// Requires the given session to have EHLO-ed, or writes a 503 response.
//checks if the current session has been opened i.e. whether the client has indicated its identity
bool session_ehlo(struct mail_session *session)
{
  return copy_response(session, session->heloed, BAD_SEQUENCE);
}


// returns true if the current session has completed the first step of mail transaction 
bool session_mail(struct mail_session *session) 
{
  return copy_response(session, session->mailed, BAD_SEQUENCE);
}

// returns true if the current session has NOT completed the first step of mail transaction  
bool session_not_mail(struct mail_session *session)
{
  return copy_response(session, !session->mailed, BAD_SEQUENCE);
}

// returns true if the current session has NOT completed the second step of mail transaction 
// Requires the given session to have not RCPT-ed, or writes a 503 response.
bool session_not_rcpt(struct mail_session *session) 
{
  return copy_response(session, session->users == NULL, BAD_SEQUENCE);
}

// Requires the given pointer to be not null, or writes a 501 response.
bool pointer_not_null(struct mail_session *session, void *pointer) 
{
  return copy_response(session, pointer != NULL, SYNTAX_ERROR_PARAM);
}

// checks if the given path is valid. If not, SYNTAX ERROR 501
bool check_path_validity(struct mail_session *session, char *path, char *head)
 {
  int headlen = strlen(head);
  int pathlen = strlen(path);

  if (pathlen > MAX_PATH_LENGTH + headlen + 2) 
  {
    strcpy(session->sendbuf, SYNTAX_ERROR_PARAM);
    return true;
  }
  return copy_response(session, strncasecmp(path, head, headlen) == 0 && path[headlen] == '<' && strcmp(&path[pathlen - 1], ">") == 0, SYNTAX_ERROR_PARAM);
}

// Requires the given session to have RCPT-ed, or writes a 503 response.
bool session_rcpt(struct mail_session *session)
{
  return copy_response(session, session->users != NULL, BAD_SEQUENCE);
}

//checks if user is valid. If not, write Mailbox Unavailable
bool check_user_validity(struct mail_session *session, char *user) 
{
  if (is_valid_user(user, NULL) == 0) {
    strcpy(session->sendbuf, MAILBOX_UNAVAILABLE);
    return true;
  }
  return false;
}

//****************

//CLIENT INITIATION -- HELO 
void HELO(struct mail_session *session)
{
  session->heloed = true;
  initialize_buffers(session);
  initialize_states(session);
  sprintf(session->sendbuf, "250 %s %s %s Ready.\r\n", session->uname->nodename, APP_NAME, APP_VER);
}

// CLIENT IDENTIFICATION -- EHLO.
void EHLO(struct mail_session *session)
{
  HELO(session);
}

//MAIL TRANSACTIONS OCCURS IN THREE STEPS: MAIL, RCPT, DATA


/* This command tells the SMTP-receiver that a new mail transaction is
   starting and to reset all its state tables and buffers, including any
   recipients or mail data */

// MAIL FROM: <reverse path>
void MAIL(struct mail_session *session)
 {
  if (session_ehlo(session) || session_not_mail(session) || session_not_rcpt(session))
    return;

  char *token = strtok(NULL, SPACE);

  if (pointer_not_null(session, token) || check_path_validity(session, token, "FROM:"))
    return;

  token = &token[6];
  token[strlen(token) - 1] = '\0';
  
  initialize_buffers(session);
  initialize_states(session);
  
  strcpy(session->reverse_path, token);
  //session->mailed = true;
  strcpy(session->sendbuf, OK);
  session->mailed = true;
}


void RCPT(struct mail_session *session) 
{
  if (session_ehlo(session) || session_mail(session))
    return;

  char *token = strtok(NULL, SPACE);

  if (pointer_not_null(session, token) || check_path_validity(session, token, "TO:"))
    return;

  token = &token[4];
  token[strlen(token) - 1] = '\0';
  if (check_user_validity(session, token))
    return;
  add_user_to_list(&session->users, token);
  strcpy(session->sendbuf, OK);
}


void DATA(struct mail_session *session) 
{

  if (session_ehlo(session) || session_mail(session) || session_rcpt(session))
    return;

  strcpy(session->sendbuf, OK_354); //START MAIL INPUT
  if (mail_send(session) <= 0)
    return;

  char data[MAX_DATA_SIZE + 1];
  char *start;
  unsigned long size_data = 0;
  int size;
  bool started = false;

  strcpy(data, NULL_STR);

  while (session->active && session->online) 
  {
    size = mail_scan(session);

    if (size <= 0)
      return;

    if (started && strncmp(session->recvbuf, ".\r\n", 3) == 0)
      break;

    if (strncmp(session->recvbuf, "..", 2) == 0)
     {
      start = &session->recvbuf[1];
      size--;
    } 
    else 
    {
      start = session->recvbuf;
    }
    size_data += size;

    if (size_data > MAX_DATA_SIZE) //ensuring data hasn't exceeded maximum limit
    {
      strcpy(session->sendbuf, EXCEEDED_STORAGE_ALLOCATION); //552, mail action aborted
      return;
    }

    strcat(data, start);
    started = true;
#ifdef DEBUG
    printf("|data|: %lu\n", size_data);
#endif
  }
  mail_write(session, data, size_data);
  initialize_buffers(session);
  initialize_states(session);
  strcpy(session->sendbuf, OK);
}


void RSET(struct mail_session *session)
 {
  initialize_buffers(session);
  initialize_states(session);
  strcpy(session->sendbuf, OK);
}


void VRFY(struct mail_session *session) 
{
  char *token = strtok(NULL, SPACE);
  if (pointer_not_null(session, token) || check_user_validity(session, token))
    return;
  sprintf(session->sendbuf, "250 %s\r\n", token);
}


void NOOP(struct mail_session *session)
{
  strcpy(session->sendbuf, OK);
}


void QUIT(struct mail_session *session)
{
  session->online = false;
  sprintf(session->sendbuf, "221 %s %s %s End.\r\n", session->uname->nodename, APP_NAME, APP_VER);
}

void deb(struct mail_session *session) 
{
  puts("  reverse_path:");
  printf("%s\n  :reverse_path\n", session->reverse_path);
  puts("  recvbuf:");
  printf("%s\n  :recvbuf\n", session->recvbuf);
  puts("  sendbuf:");
  printf("%s\n  :sendbuf\n", session->sendbuf);
  puts("  fd:");
  printf("%u\n  :fd\n", session->fd);
  puts("active\theloed\tmailed\tonline:");
  printf("%u\t%u\t%u\t%u\n:active\theloed\tmailed\tonline\n",
    session->active,
    session->heloed,
    session->mailed,
    session->online
  );
  sprintf(session->sendbuf, "250 %s %s DEBUG.\r\n", APP_NAME, APP_VER);
}


static void handle_client(int fd);

int main(int argc, char *argv[])
 {
  
    if (argc != 2) {
	fprintf(stderr, "Invalid arguments. Expected: %s <port>\n", argv[0]);
	return 1;
    }
  
    run_server(argv[1], handle_client);
  
    return 0;
}


void handle_client(int fd)
 {
    
    /* TO BE COMPLETED BY THE STUDENT */
      struct utsname my_uname;
      struct mail_session *session = malloc(sizeof(struct mail_session));

      char tempbuf[MAX_LINE_LENGTH + 1];
      char *command;

      uname(&my_uname);
      initialize_session(session, fd, &my_uname); //create this method


      while (session->active && session->online)
       {
        if (mail_scan(session) <= 0)
          break;

        if (strncmp(session->recvbuf, "\r\n", 2) == 0)
          continue;

        //Syntax error if '\r' and '\n' haven't been stripped from the string. trim returns true if it trims successfully!
        if (!trim(session->recvbuf))
            strcpy(session->sendbuf, SYNTAX_ERROR);
        
        else 
        {
            strcpy(tempbuf, session->recvbuf);
            command = strtok(tempbuf, " "); //function to split a string using some delimiter (space in this case)

          
          // switch(command)
          // {
          //   case "HELO": do_helo(session); break;
          //   case "EHLO": do_ehlo(session); break;
          //   case "MAIL": do_mail(session); break;
          //   case "RCPT": do_rcpt(session); break;
          //   case "DATA": do_data(session); break;
          //   case "RSET": do_rset(session); break;
          //   case "VRFY": do_vrfy(session); break;
          //   case "NOOP": do_noop(session); break;
          //   case "QUIT": do_quit(session); break;
          // }


          if (strcasecmp(command, "HELO") == 0)
            HELO(session);

          else if (strcasecmp(command, "EHLO") == 0)
            EHLO(session);

          else if (strcasecmp(command, "MAIL") == 0)
            MAIL(session);

          else if (strcasecmp(command, "RCPT") == 0)
            RCPT(session);

          else if (strcasecmp(command, "DATA") == 0)
            DATA(session);

          else if (strcasecmp(command, "RSET") == 0)
            RSET(session);

          else if (strcasecmp(command, "VRFY") == 0)
            VRFY(session);

          else if (strcasecmp(command, "NOOP") == 0)
            NOOP(session);

          else if (strcasecmp(command, "QUIT") == 0)
            QUIT(session);

    #ifdef DEBUG
          else if (strcasecmp(command, "dc2s") == 0)
            deb(session);
    #endif
          else
            strcpy(session->sendbuf, SYNTAX_ERROR);
        }
        if (!session->active || mail_send(session) <= 0)
          break;
      }
      nb_destroy(session->nb);
      destroy_user_list(session->users);
      free(session);
  
}
