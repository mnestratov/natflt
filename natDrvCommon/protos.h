/*
 * Copyright (C) 2015 Maxim Nestratov
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __NAT_PROTOCOLS_HEADER__
#define __NAT_PROTOCOLS_HEADER__


#ifndef ETHERNET_TYPE_IP
#define ETHERNET_TYPE_IP		0x0800
#define ETHERNET_TYPE_ARP		0x0806
#define ETHERNET_TYPE_IPV6		0x86dd

#define ETHERNET_TYPE_IP_NET	0x0008
#define ETHERNET_TYPE_ARP_NET		  0x0608
#define ETHERNET_TYPE_IPV6_NET        0xdd86
#endif

#define ETHER_ADDR_LEN          6

#define	MAX_ETHER_SIZE			1514
#define ETHERNET_HEADER_LEN		14
#define MIN_ETHER_SIZE          60

#define ARP_REQUEST_CODE		0x100
#define ARP_REPLY_CODE			0x200

#define IP_HEADER_LEN			20
#define MAX_IP_PACKET_LEN		65535

#define TCP_FIN_FLAG			0x01
#define TCP_SYN_FLAG			0x02
#define TCP_RST_FLAG			0x04
#define TCP_PSH_FLAG			0x08
#define TCP_ACK_FLAG			0x10
#define TCP_URG_FLAG			0x20
#define TCP_ECE_FLAG			0x40
#define TCP_CWR_FLAG			0x80

typedef struct _ETH_HDR
{
    unsigned char ether_dst[6];
    unsigned char ether_src[6];
    unsigned short ether_type;
} ETH_HDR;

typedef struct _ARP_HDR
{
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short ar_op;
} ARP_HDR;

typedef struct _ETH_ARP
{
    ARP_HDR ea_hdr;
    unsigned char arp_sha[6];
    unsigned char arp_spa[4];
    unsigned char arp_tha[6];
    unsigned char arp_tpa[4];
} ETH_ARP;

#define IPPROTO_IP              0             
#define IPPROTO_ICMP            1               
#define IPPROTO_TCP             6               
#define IPPROTO_UDP             17              

typedef struct _IP_HDR
{
    unsigned char ip_hlen : 4, ip_ver : 4;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_proto;
    unsigned short ip_csum;
    unsigned long ip_src;
    unsigned long ip_dst;
} IP_HDR;

typedef struct _TCP_HDR
{
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned long th_seq;
    unsigned long th_ack;
    unsigned char th_x2 : 4, th_off : 4;
    unsigned char th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;

} TCP_HDR;

#define IP_HDR_LEN(Hdr)  ((USHORT)((Hdr->ip_hlen) << 2))
#define TCP_HDR_LEN(Hdr) (Hdr->th_off << 2) 
//
// Compute the checksum
// 
#define XSUM(_TmpXsum, _StartVa, _PacketLength, _Offset)                             \
{                                                                                    \
    PUSHORT  WordPtr = (PUSHORT)((PUCHAR)_StartVa + _Offset);                        \
    ULONG    WordCount = (_PacketLength) >> 1;                                       \
    BOOLEAN  fOddLen = (BOOLEAN)((_PacketLength) & 1);                               \
    while (WordCount--)                                                              \
    {                                                                                \
        _TmpXsum += *WordPtr;                                                        \
        WordPtr++;                                                                   \
    }                                                                                \
    if (fOddLen)                                                                     \
    {                                                                                \
        _TmpXsum += (USHORT)*((PUCHAR)WordPtr);                                      \
    }                                                                                \
    _TmpXsum = (((_TmpXsum >> 16) | (_TmpXsum << 16)) + _TmpXsum) >> 16;             \
}                                                                                        

typedef struct _UDP_HDR
{
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_len;
    unsigned short uh_chk;
} UDP_HDR;

#define ICMP_ECHOREPLY          0   
#define ICMP_DEST_UNREACH       3   
#define ICMP_SOURCE_QUENCH      4   
#define ICMP_REDIRECT           5   
#define ICMP_ECHO               8   
#define ICMP_ROUTER_ADVERTISE   9   
#define ICMP_ROUTER_SOLICIT     10  
#define ICMP_TIME_EXCEEDED      11  
#define ICMP_PARAMETERPROB      12  
#define ICMP_TIMESTAMP          13  
#define ICMP_TIMESTAMPREPLY     14  
#define ICMP_INFO_REQUEST       15  
#define ICMP_INFO_REPLY         16  
#define ICMP_ADDRESS            17  
#define ICMP_ADDRESSREPLY       18  
#define NR_ICMP_TYPES           18

#define s_icmp_id         icmp_hun.idseq.id

typedef struct _ICMP_HDR {
    unsigned char type;
    unsigned char code;
    unsigned short csum;
    union {
        unsigned char pptr;
        unsigned long gwaddr;

        struct idseq {
            unsigned short id;
            unsigned short seq;
        } idseq;

        int sih_void;

        struct pmtu {
            unsigned short ipm_void;
            unsigned short nextmtu;
        } pmtu;

        struct rtradv {
            unsigned char num_addrs;
            unsigned char wpa;
            unsigned short lifetime;
        } rtradv;
    } icmp_hun;

    union {
        struct ts {
            unsigned long otime;
            unsigned long rtime;
            unsigned long ttime;
        }ts;

        struct ih_ip {
            IP_HDR *ip;
        } ip;

        struct ra_addr {
            unsigned long addr;
            unsigned long preference;
        } radv;

        unsigned long mask;

        char    data[1];

    } icmp_dun;

} ICMP_HDR;

typedef struct _echoext
{
    unsigned short id;
    unsigned short seqno;
} echoext;

typedef struct _IPv6_HDR {
    unsigned char priority : 4, ip_ver : 4;
    unsigned char flow_label[3];
    unsigned short payload_len;
    unsigned char next_header;
    unsigned char hop_limit;
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
}IPv6_HDR;

typedef struct _ICMPv6_HDR {
    unsigned char	type;
    unsigned char	code;
    unsigned short	checksum;
}ICMPv6_HDR;

typedef struct _ICMPv6_EchoRequestMsg {
    ICMPv6_HDR		hdr;
    unsigned short	id;
    unsigned short	seq_num;
    // data

}ICMPv6_EchoRequestMsg;

typedef struct _ICMPv6_NeighborSolicitationMsg {
    ICMPv6_HDR		hdr;
    unsigned long	reserved;
    unsigned char	target_addr[16];
    // Options
}ICMPv6_NeighborSolicitationMsg;

typedef struct _ICMPv6_NeighborAdvertiseMsg {
    ICMPv6_HDR		hdr;
    unsigned long	r : 1;
    unsigned long	s : 1;
    unsigned long	o : 1;
    unsigned long	reserved : 29;
    unsigned char	target_addr[16];
    // Options
}ICMPv6_NeighborAdvertiseMsg;

typedef struct _ICMPv6_LinkLayerAddrOption {
    unsigned char	type;
    unsigned char	len;
    unsigned char	macaddr[6];
}ICMPv6_LinkLayerAddrOption;

typedef struct _IPV6_pseudo_hdr {
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    unsigned long length;
    unsigned long zero : 24;
    unsigned long next_hdr : 8;
}IPV6_pseudo_hdr;


#define IPV6_ICMPV6_PROTO						0x3a

#define ICMPV6_ERROR_DESTINATION_UNREACHABLE	1
#define ICMPV6_ERROR_PACKET_TOO_BIG				2
#define ICMPV6_ERROR_TIME_EXCEEDED				3
#define ICMPV6_ERROR_PARAMETER_PROBLEM			4

#define ICMPV6_INFO_ECHO_REQUEST				128
#define ICMPV6_INFO_ECHO_REPLY					129
#define ICMPV6_INFO_ROUTER_SOLICITAION			133
#define ICMPV6_INFO_ROUTER_ADVERTISMENT			134
#define ICMPV6_INFO_NEIGHBOR_SOLICITAION		135
#define ICMPV6_INFO_NEIGHBOR_ADVERTISMENT		136

#define ICMPV6_SOURCE_LINK_LAYER_ADDR_OPT	1
#define ICMPV6_TARGET_LINK_LAYER_ADDR_OPT	2

#endif 
