#include<iostream>
#include<conio.h>
#include<iomanip>
#define HAVE_REMOTE
#include<pcap.h>//wpcap提供的头文件
#include"header.h"
#include<windows.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#define makebyte(A,B) 	
//枚举网卡 返回网卡总数
pcap_if_t* allAdapter;//存储全部网卡
unsigned int cntAdapter = 0;

int enumAdapters()
{
	//winpcap里面一个网卡使用pcap_if_t这样的一个数据结构来保存
	pcap_if_t* adapter;
	char errbuf[PCAP_BUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapter, errbuf) == -1)
	{
		cout << "搜索所有网卡失败" << endl;
		return 0;
	}
	for (adapter = allAdapter; adapter != NULL; adapter = adapter->next)
	{
		cout << ++cntAdapter <<"-"<<adapter->description << endl;
	}
	return cntAdapter;
}
//监控指定网卡
void monitorAdapter(int nChoose)
{
	pcap_if_t* adapter = allAdapter;
	for (int i = 0; i < nChoose - 1; ++i)
	{
		adapter = adapter->next;
	}
	char errbuf[PCAP_ERRBUF_SIZE];	
	//设置网卡为混杂模式(直接模式、广播模式、多播模式、混杂模式)
	//读取 超过1000毫秒进行超时处理
	pcap_t *adapterHandle = pcap_open(adapter->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000,NULL,errbuf);
	if (adapterHandle == NULL)
	{
		cout << "打开网卡失败" << endl;
		cout << errbuf << endl;
		return;
	}
	cout << "开始在网卡 " << nChoose <<"-"<<adapter->description<< " 上进行数据监听"<<endl;
	//开始进行数据的监听，需要两个结构体
	pcap_pkthdr* packetHeader;//描述头结构体
	unsigned char* packetData;//真正监听到的数据
	int retValue;
	while ((retValue = pcap_next_ex(adapterHandle, &packetHeader, &packetData)) >= 0)
	{
		if (retValue == 0)
		{
			continue;
		}
		cout << "监听信息的长度" << packetHeader->len << endl;
		break;
	}
	cout << "源MAC:";
	for (int i = 0; i < 6; i++)
	{
		cout << setw(2) << setfill('0')<<setiosflags(ios::uppercase) << hex << (int)packetData[i] << ':';
	}
	cout << '\b';
	cout << endl << "目的MAC:";
	/*for (int i = 6; i < 12; i++)
	{
		cout << setw(2) << setfill('0') << setiosflags(ios::uppercase) << hex << (int)packetData[i] << ':';
	}
	cout << endl << "TYPE:";
	for (int i = 12; i < 14; i++)
	{
		cout << setw(2) << setfill('0') << setiosflags(ios::uppercase) << hex << (int)packetData[i] << ':';
	}
	cout << '\b';
	cout << endl;*/
	_MAC_HEADER *pmac_header=new _MAC_HEADER;
	cout << endl;
	for (int i = 0; i < 6; i++)
	{
		pmac_header->dstmac[i] = packetData[i];
	}
	cout << (int)pmac_header->dstmac[0] << endl;
	return;
}
int main()
{
	cout << "找到了" << enumAdapters() << "块网卡" << endl;
	cout << "请输入要监听的网卡号:";
	int nChoose = _getch() - 0x30;
	cout << nChoose << endl;
	while (nChoose > cntAdapter || nChoose < 1)
	{
		cout << "输入错误，请重新输入网卡号：";
		nChoose = _getch() - 0x30;
		cout << nChoose << endl;
	}
	//对选择的网卡进行监控
	monitorAdapter(nChoose);
	return 0;
}