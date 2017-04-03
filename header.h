#pragma once
//һЩ����Э��Ľṹ��
//MACЭ��
#include<WinSock2.h>
typedef struct _MAC_HEADER
{
	unsigned char dstmac[6];//Ŀ��MAC
	unsigned char srcmac[6];//ԴMAC
	unsigned short type;//Э��
}mac_header, *pmac_header;
//ARPЭ��
typedef struct _ARP_HEADER
{
	unsigned short hardware;//Ӳ������
	unsigned short protocol;//Э������
	unsigned char hardwarelen;//Ӳ����ַ����(6)
	unsigned char protocollen;//Э���ַ����(4)
	unsigned short operate;//��������(1-ARP���� 2-ARPӦ�� 3-RARP���� 4-RARPӦ��)
	unsigned char sendmac[6];//���Ͷ�MAC��ַ
	in_addr sendip;//���Ͷ�IP��ַ
	unsigned char dstmac[6];//Ŀ�Ķ�MAC��ַ
	in_addr dstip;//Ŀ�Ķ�IP��ַ
}arp_header, *parp_header;
//RARPЭ��
typedef struct _RARP_HEADER
{
	unsigned short hardware;//Ӳ������
	unsigned short protocol;//Э������
	unsigned char hardwarelen;//Ӳ����ַ����(6)
	unsigned char protocollen;//Э���ַ����(4)
	unsigned short operate;//��������(1-ARP���� 2-ARPӦ�� 3-RARP���� 4-RARPӦ��)
	unsigned char sendmac[6];//���Ͷ�MAC��ַ
	unsigned char sendip[4];//���Ͷ�IP��ַ
	unsigned char dstmac[6];//Ŀ�Ķ�MAC��ַ
	unsigned char dstip[4];//Ŀ�Ķ�IP��ַ
}rarp_header, prarp_header;
//IPЭ��
typedef struct _IP_HEADER
{
	unsigned char headerlen : 4;   //�ײ�����
	unsigned char version : 4; //�汾 
	unsigned char tos;   //��������
	unsigned short total_len; //�ܳ���
	unsigned short id;    //��־
	unsigned short frag_off; //��Ƭƫ��
	unsigned char ttl;   //����ʱ��
	unsigned char protocol; //Э��
	unsigned short chk_sum; //�����
	struct in_addr srcaddr; //ԴIP��ַ
	struct in_addr dstaddr; //Ŀ��IP��ַ
}ip_header, *pip_header;
//TCPЭ��
typedef struct _TCP_HEADER
{
	unsigned short srcport;//Դ�˿�
	unsigned short dstport;//Ŀ�Ķ˿�
	unsigned int seq_no;//���к�
	unsigned int ack_no;//ȷ�Ϻ�
	unsigned char reserved_1 : 4;//����λ
	unsigned char headerlen : 4;//Э��ͷ����
	unsigned char flag : 6;//6λ��־
	unsigned char reserved_2 : 2;//����λ
	unsigned short wnd_size;//���ڴ�С
	unsigned short chk_sum;//У���
	unsigned short urgt_p;//����ָ��
}tcp_header, *ptcp_header;
//UDPЭ��
typedef struct _UDP_HEADER
{
	unsigned short srcport;//Դ�˿ں�
	unsigned short dstport;//Ŀ�Ķ˿ں�
	unsigned short headerlen;//UDP����
	unsigned short chk_sum;//У���
}udp_header, *pudp_header;
//ICMPЭ��
typedef struct _ICMP_HEADER
{
	unsigned char type;//����
	unsigned char code;//����
	unsigned short chk_sum;//У���
}icmp_header, *picmp_header;
//IGMP
typedef struct _IGMP_HEADER
{
	unsigned char type : 4;//����
	unsigned char version : 4;//�汾
	unsigned char reserved;//δ��
	unsigned short chk_sum;//У���
	in_addr addr;//D��IP��ַ
}igmp_header, *pigmp_header;