#pragma once
#include <linux/in.h>


// DNS header structure
struct dnshdr {
  __u16 id; // identification number

  __u8 rd : 1;     // recursion desired
  __u8 tc : 1;     // truncated message
  __u8 aa : 1;     // authoritive answer
  __u8 opcode : 4; // purpose of message
  __u8 qr : 1;     // query/response flag

  __u8 rcode : 4; // response code
  __u8 cd : 1;    // checking disabled
  __u8 ad : 1;    // authenticated data
  __u8 z : 1;     // its z! reserved
  __u8 ra : 1;    // recursion available

  __u16 q_count;    // number of question entries
  __u16 ans_count;  // number of answer entries
  __u16 auth_count; // number of authority entries
  __u16 add_count;  // number of resource entries
};