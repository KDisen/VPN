#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

/* vpnclient packages */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
//-----------------------
//auth.c packages
#include <shadow.h>
#include <crypt.h>
#include <termios.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <stdlib.h>
//----------------------

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"

/* vpnclient definitions */
#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.5"
//------------------------


/* VPN methods to create tunnel */
struct sockaddr_in peerAddr;

SSL *ssl;

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
    buff[len] = '\0';
    // WED SSL_write(ssl, buff, len);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

void socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);//SSL_read(ssl, buff, BUFF_SIZE);
    //buff[len] = '\0';
    write(tunfd, buff, len);

}

/*int login(char *user, char *passwd){
  struct spwd *pw;
  char *epasswd;
  pw = getspnam(user);
  if (pw == NULL) {
    return -1;
  }
  printf("Login name: %s\n", pw->sp_namp);
  printf("Passwd : %s\n", pw->sp_pwdp);
  epasswd = crypt(passwd, pw->sp_pwdp);
  if (strcmp(epasswd, pw->sp_pwdp)) {
    return -1;
  }
  return 1;
}*/

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;


   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
   printf(ssl);
   //printf("ll\n");

   return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
//   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));
   //printf("TCP is established wih the hostname IP: %s and port: %d\n", inet_ntoa(server_addr.sin_addr), port);
   printf("TCP is established");

   return sockfd;
}


int main(int argc, char *argv[])
{
   int tunfd;

   tunfd  = createTunDevice();

   char *hostname = "yahoo.com";
   int port = 443;

   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/

   SSL *ssl   = setupTLSClient(hostname);
   printf("TLS initialized\n");
   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);
   printf("TCP connecting beginning\n");

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   /*----------------Send/Receive data --------------------*/
   /*char buf[9000];
   char sendBuf[200];
   sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   SSL_write(ssl, sendBuf, strlen(sendBuf));
*/
   /*int len;
   do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
   } while (len > 0);*/

   char password[100];
   char username[50];
   //char *passwd;

   printf("Please enter your username: \n");
   scanf("%s", username);
   printf("Please enter your password: \n");

   struct termios pass;

   tcgetattr(STDIN_FILENO, &pass);
   pass.c_lflag &= ~ECHO; //turn off terminal when typing
   tcsetattr(STDIN_FILENO, 1, &pass);
   scanf("%s", password);
   pass.c_lflag |= ECHO; //turn on terminal
   tcsetattr(STDIN_FILENO, 0, &pass);
   //strcat(username, " "); //add a space to username

   //char salt = "ky";
   //RAND_bytes(salt, sizeof(salt));

   //use the pw-> stuff to store the local hash, then send over that hash, I believe you wont have to crypt it on that end since it's already hashed, just compare it.

   struct spwd *pw;
   char *epasswd;
   pw = getspnam(username);
   strcat(username, " "); //add a space to username

   epasswd = crypt(password, pw->sp_pwdp);
   //printf("%s\n", epasswd);
   strcat(username,epasswd); //add the password to the username var


   char buf[100];
   char sendBuf[100];
   sprintf(sendBuf,"%s", username); //put variable into buffer
   SSL_write(ssl, sendBuf, strlen(sendBuf)); //send buffer over the network to VPN Server

   int len;
   do {
      len = SSL_read(ssl, buf, sizeof(buf) - 1);
      buf[len] = '\0';
      printf("%s\n", buf);
   } while (len > 0);

   int stop = 0;
   for(int i=0;i<sizeof(buf);i++){
      if (isdigit(buf[i])!=0) stop = buf[i];
   }
   if (stop == 1) return 0;
   else{
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);


     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
   }
   }
}
