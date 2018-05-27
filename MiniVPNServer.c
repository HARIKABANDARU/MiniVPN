
////////////////////////////////////////////////////////////////////////////////
//  TLSMultiClinetServer.c   -  This program listens for multiple TCP Clients //
//  ver 1.0                                                                   //
//  Language:          C   2017                                               //
//  Platform:         DELL XPS 5 Windows 10                                   //
//  Application :     Mini-VPN SP18    //
//  Author      :     Harika Bandaru, Syracuse University                     //
//                    hbandaru@syr.edu (936)-242-5972)                        //
////////////////////////////////////////////////////////////////////////////////
/*
* Modular Operations
=====================
*The TLSMultiServer program have IPC through PIPES to communicate with the child process
*and write messages to the child using the fd[1] of the pipe and the child keeps listening to
* the multiple descriptors achieved using "select" function the tunPipeFd of the child reads data
* from pipe using fd[0] and write over the SSL layer
* public:
* ===========
* hash_string    : Used by the Dictionary to have a faster lookup.
* Entry_create    : Creates an Entry in the Dictionary.
* Dictionary_put  : To write an entry to the dictionary data structure.
* Dictionary_get  : To read the value based on the key passed form the Dictionary data structure.
* loginCheck      : Used for the ClientAuthentication Purpose by the Server
* createTunDevice : To open a tun device using "dev/net/tun"
* initUDPServer   : Used initially when UDP was setup
* setupTCPServer  : To set-up TCP Server as TLS/SSl should be combined with TCP
* tunSelected    : Called when data was given to the Tun interface.
* tunPipeSelected : Called by the Child Process when it sees data in the Pipewhich it is listening for
* socketSelected  : Called when the data was found in the socket.
* InitServerCTX   : To initialisize the OPEnssl requied callbacks for the PKI certificate check.
* LoadCertificates : To load Private Key of the server and the certifcate of the server.
* startChildProcess : To start the Child Process that listens on the PipeFd and the sockfd.
* ParentProcess   : To accept and listen data from the Private network sent by the client
*  Build Process:
*  ================
*  Required files:
*  -------------------
*  assignIp.sh forwardSet.sh
*
*  Command:
* ----------------
* gcc -g -o Server TLServerMultiClient.c -lcrypto -lssl -lcrypt
*
*  Maintenanace History:
*  ======================
*  ver 1.0
*  */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdarg.h>
#include <shadow.h>
#include <crypt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <string.h>

struct ipheader {
unsigned char      iph_ihl : 4, iph_ver : 4; //IP Header length & Version.
unsigned char      iph_tos; //Type of service
unsigned short int iph_len; //IP Packet length (Both data and header)
unsigned short int iph_ident; //Identification
unsigned short int iph_flag : 3, iph_offset : 13; //Flags and Fragmentation offset
unsigned char      iph_ttl; //Time to Live
unsigned char      iph_protocol; //Type of the upper-level protocol
unsigned short int iph_chksum; //IP datagram checksum
struct  in_addr    iph_sourceip; //IP Source address (In network byte order)
struct  in_addr    iph_destip;//IP Destination address (In network byte order)
};
#define HASHSIZE 101

#define DICT_SIZE 501 



#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }


#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define tunip_addr "192.168.53"

//----------< Dictionary taken from Github >--------------------
typedef struct Entry {
char *key;
int pipeFd;
struct Entry *next;
} Entry;

typedef struct Dictionary {
unsigned size;
Entry *table[DICT_SIZE];
} Dictionary;



unsigned hash_string(unsigned char *str) {
unsigned hash = 5381;
int c;

while ((c = (*str++)))
hash = ((hash << 5) + hash) + c;

return hash % DICT_SIZE;
}


Entry* Entry_create(char *key, int value) {
Entry *e = malloc(sizeof(Entry));
e->key = key;
e->pipeFd = value;
e->next = NULL;
return e;
}


/*
* Create and return a new Dictionary object
*/
Dictionary* Dictionary_new() {
Dictionary *d = malloc(sizeof(Dictionary));
for (int i = 0; i < DICT_SIZE; i++)
d->table[i] = NULL;
return d;
}

/*
* Bind value to a given key in the dictionary
*
* If the specified key already exists, the existing bound
* value is replaced with the new value
*/
void Dictionary_put(Dictionary *d, char *key, int value) {

unsigned hash = hash_string((unsigned char *)key);

if (!d->table[hash]) {
d->table[hash] = Entry_create(key, value);
return;
}

for (Entry *i = d->table[hash]; i; i = i->next) {
if (strcmp(key, i->key) == 0) {
i->pipeFd = value;
return;
}
if (i->next == NULL) {
i->next = Entry_create(key, value);
return;
}
}

}


/*
* Get and return the string value stored at
* a given key
*
* Returns NULL if key is not found
*/
int Dictionary_get(Dictionary *d, char *key) {

unsigned hash = hash_string((unsigned char *)key);
for (Entry *i = d->table[hash]; i; i = i->next) {
if (strcmp(key, i->key) == 0)
return i->pipeFd;
}
return NULL;
}
//Dictionary *d = Dictionary_new();

struct in {
char *name;
struct in_addr   ip_addr;
};

struct sockaddr_in peerAddr;

//---------------------------------< Login functionality >--------------------------

int loginCheck(char *user, char *passwd)
{
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
printf("Client Authenicated Successfully");
return 1;
}


//----------------------< Source Simpletn.c >---------------------------
/**************************************************************************
* my_err: prints custom error messages on stderr.                        *
**************************************************************************/
void my_err(char *msg, ...) {

va_list argp;

va_start(argp, msg);
vfprintf(stderr, msg, argp);
va_end(argp);
}
//----------------< Creaating Tun device >------------
int createTunDevice() {
int tunfd, err;
struct ifreq ifr;
memset(&ifr, 0, sizeof(ifr));

ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
//-------------< oprning a tun device and registering it with usage of ioctl api >-------------
tunfd = open("/dev/net/tun", O_RDWR);
//--------< Added error cheching while opening tun device >-------------
if ((err = ioctl(tunfd, TUNSETIFF, (void *)&ifr)) < 0) {
perror("ioctl(TUNSETIFF)");
close(tunfd);
return err;
}
return tunfd;
}


//---------------< UDP Server used intially >---------------
int initUDPServer() {
int sockfd;
struct sockaddr_in server;
char buff[100];

memset(&server, 0, sizeof(server));
server.sin_family = AF_INET;
server.sin_addr.s_addr = htonl(INADDR_ANY);
server.sin_port = htons(PORT_NUMBER);

if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
perror("Socket()");
exit(1);
}
bind(sockfd, (struct sockaddr*) &server, sizeof(server));

// Wait for the VPN client to "connect".
bzero(buff, 100);
int peerAddrLen = sizeof(struct sockaddr_in);
int len = recvfrom(sockfd, buff, 100, 0,
(struct sockaddr *) &peerAddr, &peerAddrLen);
//---------------< Debug statement >---------------
// printf("Connected with the client: %s\n", buff);
return sockfd;
}
//----------< TCP Server Set-up >----------------
int setupTCPServer()
{
struct sockaddr_in sa_server;
int listen_sock;

listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
CHK_ERR(listen_sock, "socket");
memset(&sa_server, '\0', sizeof(sa_server));
sa_server.sin_family = AF_INET;
sa_server.sin_addr.s_addr = INADDR_ANY;
sa_server.sin_port = htons(4433);
int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
CHK_ERR(err, "bind");
err = listen(listen_sock, 5);
CHK_ERR(err, "listen");
return listen_sock;
}

//-----------------< tunneel/tap interface selected >-----------------
void tunSelected(int tunfd, Dictionary *d) {
int  len;
char buff[BUFF_SIZE];
bzero(buff, BUFF_SIZE);
len = read(tunfd, buff, sizeof(buff));
if (len < 0)
{
perror("Reading Data");
exit(1);
}

struct ipheader *ip = (struct ipheader *)buff;
//printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
int writeFd = Dictionary_get(d, inet_ntoa(ip->iph_destip));
write(writeFd, buff, len);
//SSL_write(ssl, buff, len);
}


//-----------------< tunneel/tap interface selected >-----------------
void tunPipeSelected(int readPipefd, int sockfd, SSL *ssl) {
int  len;
char buff[BUFF_SIZE];
bzero(buff, BUFF_SIZE);
len = read(readPipefd, buff, sizeof(buff));
if (len < 0)
{
perror("Reading Data");
exit(1);
}
SSL_write(ssl, buff, len);
}

//------------------< Socket interface selected >------------
void socketSelected(int tunfd, int sockfd, SSL *ssl) {
int  len;
char buff[BUFF_SIZE];
bzero(buff, BUFF_SIZE);
len = SSL_read(ssl, buff, sizeof(buff));
write(tunfd, buff, len);
}

//-----------------------------< Client Authentication >--------------
int ClientAuthntecate(SSL *ssl)
{
char username[50];
char password[50];
char buff[BUFF_SIZE];
bzero(buff, BUFF_SIZE);
int readl = SSL_read(ssl, buff, BUFF_SIZE);
char *p;
p = strtok(buff, "@");
strcpy(username, p);
p = strtok(NULL, "@");
strcpy(password, p);
int auth = loginCheck(username, password);
if (auth == -1)
{
printf("Incorrect credentials");

return 0;
}
else
{
printf("Client Verified successfully");


return 1;

}

}

//-------------------------< Initialize the context for SSL connections as it is stateful protocol >---------
SSL_CTX* InitServerCTX(void)
{
SSL_METHOD *meth;
SSL_CTX* ctx;
// Step 0: OpenSSL library initialization 
// This step is no longer needed as of version 1.1.0.
SSL_library_init();
SSL_load_error_strings();
SSLeay_add_ssl_algorithms();
// Step 1: SSL context initialization
meth = (SSL_METHOD *)TLSv1_2_method();
ctx = SSL_CTX_new(meth);
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
if (ctx == NULL)
{
printf("CTX Initialisation failed");
exit(1);
}

}

//--------------------< Load server certificates that acts as Server authentication system >-------------
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
// Step 2: Set up the server certificate and private key
if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
{
printf("unable to load server authentication certificate");
exit(1);
}
/* set the private key from KeyFile (may be the same as CertFile) */
if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
{
printf("unable to load server private key ");
exit(1);
}
}

void startChildProcess(int sockfd, int readPipeFd, SSL *ssl, int tunfd, char *ip)
{
//----------------< user authentication >---------------
char *username;
char *password;
char buff[BUFF_SIZE];
bzero(buff, BUFF_SIZE);
int readl = SSL_read(ssl, buff, BUFF_SIZE);
char *p;
username = strtok(buff, "@");
password = strtok(NULL, "@");
int auth = loginCheck(username, password);
char *sucess = "suucessful";

sprintf(buff, "%s@%s", sucess, ip);
char *invalid = "invalid";
if (auth == -1)
{
printf("Client Authentication failed\n");
SSL_write(ssl, invalid, strlen(invalid));
SSL_shutdown(ssl);
SSL_free(ssl);
close(sockfd);
return;
}
printf("\n User authentication successfull");
SSL_write(ssl, buff, strlen(buff));



while (1) {
fd_set readFDSet;
int ret;
FD_ZERO(&readFDSet);
FD_SET(sockfd, &readFDSet);
FD_SET(readPipeFd, &readFDSet);
ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
if (ret < 0 && errno == EINTR)
continue;
if (ret < 0) {
printf("eneterd to error");
perror("Select()");
exit(1);
}

if (FD_ISSET(readPipeFd, &readFDSet)) {
tunPipeSelected(readPipeFd, sockfd, ssl);
}

if (FD_ISSET(sockfd, &readFDSet)) { socketSelected(tunfd, sockfd, ssl); }

}
}

void parentProcess(int listen_sock, int readFd, int tunfd, SSL_CTX *ctx, Dictionary *d, char *ip)
{
struct sockaddr_in sa_client;
size_t client_len;
client_len = sizeof(sa_client);
memset(&sa_client, '\0', client_len);
int sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);


if (fork() == 0) {
close(listen_sock);
SSL *ssl;
ssl = SSL_new(ctx);
SSL_set_fd(ssl, sockfd);
int err = SSL_accept(ssl);
CHK_SSL(err);
printf("\nSSL connection established!\n");
startChildProcess(sockfd, readFd, ssl, tunfd, ip);
close(sockfd);
}
else
{
close(sockfd);
}

}

//----------< Program execution start here >-----------------

int main(int argc, char * argv[])
{

Dictionary *d = Dictionary_new();
int tunfd, listen_sock;
int fd[2];
pid_t pid;
int tun_increment = 4;
SSL_CTX *ctx;
if (pipe(fd) == -1)
{
fprintf(stderr, "Pipe Failed");
return 1;
}
ctx = InitServerCTX();
LoadCertificates(ctx, "./cert_server/hbandaru_cert.pem", "./cert_server/hbandaru_key.pem");



//------< Creating the socket interface >-------
if ((tunfd = createTunDevice()) < 0) {
my_err("Error connecting to tun/tap device interface");
exit(1);
}


listen_sock = setupTCPServer();

while (1) {
fd_set readFDSet;
int ret;
char *ip;
ip = (char *)malloc(sizeof(char) * 40);

FD_ZERO(&readFDSet);
FD_SET(listen_sock, &readFDSet);
FD_SET(tunfd, &readFDSet);
ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
if (ret < 0 && errno == EINTR)
continue;
if (ret < 0) {
printf("eneterd to error");
perror("Select()");
exit(1);
}

if (FD_ISSET(tunfd, &readFDSet)) {
tunSelected(tunfd, d); //write to fd[1]
}

if (FD_ISSET(listen_sock, &readFDSet)) {
int fd[2];
if (pipe(fd) == -1)
{
fprintf(stderr, "Pipe Failed");
return 1;
}
tun_increment++;
sprintf(ip, "%s.%d", tunip_addr, tun_increment);
int len = strlen(ip);
ip[len] = '\0';
printf("\nIpaddress Generated Dynamically::%s", ip);
Dictionary_put(d, ip, fd[1]);
parentProcess(listen_sock, fd[0], tunfd, ctx, d, ip);
} //Read from fd[0]




}
}