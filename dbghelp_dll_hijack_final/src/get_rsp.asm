

.code
GetRspValue proc
    mov rax, rsp
    ret 
GetRspValue endp  
GetRbpValue proc
    mov rax, rbp
    ret 
GetRbpValue endp
GetRdiValue proc
    mov rax, rdi
    ret 
GetRdiValue endp
end                      
