.intel_syntax noprefix
.global main
.text
main:
	mov rax, 333
	syscall

	xchg rax, rdi
	mov rax, 60
	syscall
