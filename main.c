#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include "ether.h"
#include "ip.h"
#include "icmp.h"
#include "packetAnalyze.h"

long sendDataLen(FILE *fp)
{
	long size;
	fseek(fp,0,SEEK_END);
	size = ftell(fp);
	fseek(fp,0,SEEK_SET);
	return size;
}

int getData(int device)
{
	printf("getData\n");	
	FILE *getFile;
	int size;
	int lest;  //icmp data len
	u_char message[1500 - 20];
	u_char data[1000];
	for(;;){
		getFile = fopen("getFileTest.jpeg","ab");
		size = read(device,message,sizeof(message));
		if((lest = Analyze(message,size,data))){
			fwrite(data,1,lest,getFile);
			if(lest < 1000){ 
				fwrite(data,1,lest,getFile);
				break;
			}
		}
	}
	fclose(getFile);
	return 0;
}

int main(int argc,char *argv[])
{
	FILE *file;
	file = fopen(argv[2],"rb");
	long fileSize;

	int driver;
	int len;
	char *hdst = "08:00:27:66:5d:29";
	char *hsrc = "c4:b3:01:bf:9a:ed";
	char *psrc = "192.168.1.5";
	char *pdst = "192.168.1.2";

	driver = DriverUp(argv[1],0,0);
	if(argc!=3){
		getData(driver);
		return 0;
	}
	
	fileSize = sendDataLen(file);
	u_char pkt[1514];
	long i;
	for(i=0;i+1000<fileSize;i+=1000){
		if(fileSize<1000){
			break;
		}
		fread(pkt,1,1000,file);
		fseek(file,i+1000,SEEK_SET);
		len = Ether(Ip(Icmp(1000,pkt,8,0),pkt,0x01,psrc,pdst),pkt,hsrc,hdst,0x0800);
		write(driver,pkt,len);
	}
	
fread(pkt,1,fileSize-i,file);
	len = Ether(Ip(Icmp(fileSize-i,pkt,8,0),pkt,0x01,psrc,pdst),pkt,hsrc,hdst,0x0800);
	write(driver,pkt,len);
	fclose(file);
	return 0;
}
