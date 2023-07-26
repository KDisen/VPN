#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

/* vpnserver packages */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
//-------------------------

//auth packages
#include <shadow.h>
#include <crypt.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

/* vpnserver definitions */
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
//-------------------------

struct sockaddr_in peerAddr;
int  setupTCPServer();                   // Defined in Listing 19.10
//void processRequest(SSL* ssl, int sock, int tunfd); // Defined in Listing 19.12

/* vpnserver creating tunnel */

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);

   return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
    //buff[len] = '\0';
    //SSL_write(ssl, buff, len);
}

void socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    //len = SSL_read(ssl, buff, BUFF_SIZE);
    //buff[len] = '\0';
    write(tunfd, buff, len);

}
//-------------------------------------------------------------------


int main(){

  int tunfd;
  tunfd = createTunDevice();

  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();

  SSL_METHOD *meth;
       SSL_CTX* ctx;
       SSL *ssl;
       int err;

  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
       SSL_library_init();
       SSL_load_error_strings();
       SSLeay_add_ssl_algorithms();

   // Step 1: SSL context initialization
       meth = (SSL_METHOD *)TLSv1_2_method();
       ctx = SSL_CTX_new(meth);
       SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

   // Step 2: Set up the server certificate and private key
       SSL_CTX_use_certificate_file(ctx, "./cert_server2/serverCert.pem", SSL_FILETYPE_PEM);
       SSL_CTX_use_PrivateKey_file(ctx, "./cert_server2/serverKey.pem", SSL_FILETYPE_PEM);

   // Step 3: Create a new SSL structure for a connection
       ssl = SSL_new (ctx);

  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process

       close(listen_sock);

       SSL_set_fd (ssl, sock);
       err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");



       //printf("%s\n", password);

       /*while(buf[i] != " "){
          username[j] = buf[i];
          //printf("%c\n", buf[i]);
          i++;
          j++;
       }
       j++;
       int k=0;
       while(buf[j] != " "){
          password[k] = buf[j];
          //printf("%c\n", buf[j]);
          k++;
          j++;
       }*/

       //Receive information from Host U
       char buf[1024];
       bzero(buf, sizeof(buf));
       int len = SSL_read (ssl, buf, sizeof(buf) - 1);
       buf[len] = '\0';

       char username[50];
       char password[100];
       int i=0, j=0;
       printf("%s\n", buf);
       //int size = strlen(buf);

       //manipulate string and separating username and
       //hashed password into different variables
       char *token;
       token = strtok(buf, " ");
       strcpy(username, token);
       token = strtok(NULL, " ");
       strcpy(password, token);

       printf("user: %s\n", username);
       //printf("Size %d\n", sizeof(username));
       int res=0;
       res = processRequest(username, password);

       if (res == -1){
          printf("Authenticated!!!\n");
          while (1) {
             fd_set readFDSet;
             FD_ZERO(&readFDSet);
             FD_SET(sock, &readFDSet);
             FD_SET(tunfd, &readFDSet);
             select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

             if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sock,ssl);
             if (FD_ISSET(sock, &readFDSet)) socketSelected(tunfd, sock, ssl);

          }
          }else {
              char sendBuf[100];
              char *deny = "Not authenticated... Shutting down";
              sprintf(sendBuf, deny);

              SSL_write(ssl, sendBuf, strlen(sendBuf));
              return 0;

          }



    } else { // The parent process
        close(sock);
        close(tunfd);
    }

  }
}


int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int processRequest(char *user, char *passwd)
{

    struct spwd *pw;
    //char *epasswd;
    pw = getspnam(user);

    if(pw == NULL) return 2;
    for(int i=0; i<sizeof(passwd);i++){
       if (passwd[i] != pw->sp_pwdp[i]){
         printf("no match %s\n", pw->sp_pwdp[i]);
         return 1;
       } else return -1;
    }


    //printf("Login name: %s\n", pw->sp_namp);
    //printf("Passwd : %s\n", pw->sp_pwdp);

    //epasswd = crypt(passwd, pw->sp_pwdp);
    //printf("%s\n", epasswd);
    //if (strcmp(passwd, pw->sp_pwdp)){ //was not working when comparing both hashes
      // return -1;







    // Construct and send the HTML page
    /*char *html =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));*/
    //SSL_shutdown(ssl);  SSL_free(ssl);
}
