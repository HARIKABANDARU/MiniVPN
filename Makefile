all: 
	gcc -o Server VpnServer.c
	gcc -o Client VPNClient.c

clean: 
	rm Server Client Server
