#include<iostream>
#include<conio.h>
#include<iomanip>
#define HAVE_REMOTE
#include<pcap.h>//wpcap�ṩ��ͷ�ļ�
#include"header.h"
#include<windows.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#define makebyte(A,B) 	
//ö������ ������������
pcap_if_t* allAdapter;//�洢ȫ������
unsigned int cntAdapter = 0;

int enumAdapters()
{
	//winpcap����һ������ʹ��pcap_if_t������һ�����ݽṹ������
	pcap_if_t* adapter;
	char errbuf[PCAP_BUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapter, errbuf) == -1)
	{
		cout << "������������ʧ��" << endl;
		return 0;
	}
	for (adapter = allAdapter; adapter != NULL; adapter = adapter->next)
	{
		cout << ++cntAdapter <<"-"<<adapter->description << endl;
	}
	return cntAdapter;
}
//���ָ������
void monitorAdapter(int nChoose)
{
	pcap_if_t* adapter = allAdapter;
	for (int i = 0; i < nChoose - 1; ++i)
	{
		adapter = adapter->next;
	}
	char errbuf[PCAP_ERRBUF_SIZE];	
	//��������Ϊ����ģʽ(ֱ��ģʽ���㲥ģʽ���ಥģʽ������ģʽ)
	//��ȡ ����1000������г�ʱ����
	pcap_t *adapterHandle = pcap_open(adapter->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000,NULL,errbuf);
	if (adapterHandle == NULL)
	{
		cout << "������ʧ��" << endl;
		cout << errbuf << endl;
		return;
	}
	cout << "��ʼ������ " << nChoose <<"-"<<adapter->description<< " �Ͻ������ݼ���"<<endl;
	//��ʼ�������ݵļ�������Ҫ�����ṹ��
	pcap_pkthdr* packetHeader;//����ͷ�ṹ��
	unsigned char* packetData;//����������������
	int retValue;
	while ((retValue = pcap_next_ex(adapterHandle, &packetHeader, &packetData)) >= 0)
	{
		if (retValue == 0)
		{
			continue;
		}
		cout << "������Ϣ�ĳ���" << packetHeader->len << endl;
		break;
	}
	cout << "ԴMAC:";
	for (int i = 0; i < 6; i++)
	{
		cout << setw(2) << setfill('0')<<setiosflags(ios::uppercase) << hex << (int)packetData[i] << ':';
	}
	cout << '\b';
	cout << endl << "Ŀ��MAC:";
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
	cout << "�ҵ���" << enumAdapters() << "������" << endl;
	cout << "������Ҫ������������:";
	int nChoose = _getch() - 0x30;
	cout << nChoose << endl;
	while (nChoose > cntAdapter || nChoose < 1)
	{
		cout << "����������������������ţ�";
		nChoose = _getch() - 0x30;
		cout << nChoose << endl;
	}
	//��ѡ����������м��
	monitorAdapter(nChoose);
	return 0;
}