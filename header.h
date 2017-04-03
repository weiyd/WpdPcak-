#pragma once
//一些网络协议的结构体
//MAC协议
#include<WinSock2.h>
typedef struct _MAC_HEADER
{
	unsigned char dstmac[6];//目的MAC
	unsigned char srcmac[6];//源MAC
	unsigned short type;//协议
}mac_header, *pmac_header;
//ARP协议
typedef struct _ARP_HEADER
{
	unsigned short hardware;//硬件类型
	unsigned short protocol;//协议类型
	unsigned char hardwarelen;//硬件地址长度(6)
	unsigned char protocollen;//协议地址长度(4)
	unsigned short operate;//操作类型(1-ARP请求 2-ARP应答 3-RARP请求 4-RARP应答)
	unsigned char sendmac[6];//发送端MAC地址
	in_addr sendip;//发送端IP地址
	unsigned char dstmac[6];//目的端MAC地址
	in_addr dstip;//目的端IP地址
}arp_header, *parp_header;
//RARP协议
typedef struct _RARP_HEADER
{
	unsigned short hardware;//硬件类型
	unsigned short protocol;//协议类型
	unsigned char hardwarelen;//硬件地址长度(6)
	unsigned char protocollen;//协议地址长度(4)
	unsigned short operate;//操作类型(1-ARP请求 2-ARP应答 3-RARP请求 4-RARP应答)
	unsigned char sendmac[6];//发送端MAC地址
	unsigned char sendip[4];//发送端IP地址
	unsigned char dstmac[6];//目的端MAC地址
	unsigned char dstip[4];//目的端IP地址
}rarp_header, prarp_header;
//IP协议
typedef struct _IP_HEADER
{
	unsigned char headerlen : 4;   //首部长度
	unsigned char version : 4; //版本 
	unsigned char tos;   //服务类型
	unsigned short total_len; //总长度
	unsigned short id;    //标志
	unsigned short frag_off; //分片偏移
	unsigned char ttl;   //生存时间
	unsigned char protocol; //协议
	unsigned short chk_sum; //检验和
	struct in_addr srcaddr; //源IP地址
	struct in_addr dstaddr; //目的IP地址
}ip_header, *pip_header;
//TCP协议
typedef struct _TCP_HEADER
{
	unsigned short srcport;//源端口
	unsigned short dstport;//目的端口
	unsigned int seq_no;//序列号
	unsigned int ack_no;//确认号
	unsigned char reserved_1 : 4;//保留位
	unsigned char headerlen : 4;//协议头长度
	unsigned char flag : 6;//6位标志
	unsigned char reserved_2 : 2;//保留位
	unsigned short wnd_size;//窗口大小
	unsigned short chk_sum;//校验和
	unsigned short urgt_p;//紧急指针
}tcp_header, *ptcp_header;
//UDP协议
typedef struct _UDP_HEADER
{
	unsigned short srcport;//源端口号
	unsigned short dstport;//目的端口号
	unsigned short headerlen;//UDP长度
	unsigned short chk_sum;//校验和
}udp_header, *pudp_header;
//ICMP协议
typedef struct _ICMP_HEADER
{
	unsigned char type;//类型
	unsigned char code;//代码
	unsigned short chk_sum;//校验和
}icmp_header, *picmp_header;
//IGMP
typedef struct _IGMP_HEADER
{
	unsigned char type : 4;//类型
	unsigned char version : 4;//版本
	unsigned char reserved;//未用
	unsigned short chk_sum;//校验和
	in_addr addr;//D类IP地址
}igmp_header, *pigmp_header;