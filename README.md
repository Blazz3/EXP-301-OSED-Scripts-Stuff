# EXP-301 (OSED) Scripts & Stuff

This is a collection of scripts and tools that I used extensively throughout this great EXP-301 course. You can install the dependencies with:

```bash
python -m pip install requirements.txt
```

## Compute Hash

Compute hash from EXP-301 PDF, supports a different key. Credits to [Offsec](https://www.offsec.com/).

Example:
```bash
python compute_hash.py -s 'WSAConnect' -k 0xd

KEY: 0xd
push 0xb32dba0c
```

## Stack String

Prints the assembly code to push a STRING onto the stack, supports NEG method to avoid NULL bytes.

Example:
```bash
python stack_string.py -f 'example'   

ASM                    Comments                  
                                                 
xor eax, eax           ; eax = 0                 
push eax               ; Ensure NULL byte        
push 0x656c70          ; Push 'elp'              
push 0x6d617865        ; Push 'maxe'             

python stack_string.py -f 'example' -n

ASM                        Comments                             
                                                                
xor eax, eax               ; eax = 0                            
push eax                   ; Ensure NULL byte                   
                                                                
mov edx, 0xff9a9390        ; 'elp' = 0x656c70                   
neg edx                    ; 0 - 0x656c70 = 0xff9a9390          
push edx                   ; push 0xff9a9390                    
                                                                
mov edx, 0x929e879b        ; 'maxe' = 0x6d617865                
neg edx                    ; 0 - 0x6d617865 = 0x929e879b        
push edx                   ; push 0x929e879b 
```

## Some regex to find useful gadgets

```bash
1 - CONTROL ESP
mov e.., esp 
push esp.*pop e.. 

2 - REGISTRY CONTROL
mov (eax|ebx|ecx|edx|esi|edi|ebp), (eax|ebx|ecx|edx|esi|edi|ebp) 
push (eax|ebx|ecx|edx|esi|edi|ebp).*pop (eax|ebx|ecx|edx|esi|edi|ebp) 
xchg (dword )?(\[)?(e..|e..\[+-]0x[0-9]{1,8}|e..\+e..)(\])?, (dword )?(\[)?(e..|e..\+0x[0-9]{1,8}|e..\+e..)(\])? 
pop (eax|ebx|ecx|edx|esi|edi|ebp) 
lea (eax|ebx|ecx|edx|esi|edi|ebp) 

3 - UTILITY
push (eax|ebx|ecx|edx|esi|edi|ebp) 
xor (eax|ebx|ecx|edx|esi|edi|ebp), (eax|ebx|ecx|edx|esi|edi|ebp| \[) 
[^x]or (eax|ebx|ecx|edx|esi|edi|ebp), (eax|ebx|ecx|edx|esi|edi|ebp| \[) 
(neg|not) (eax|ebx|ecx|edx|esi|edi|ebp) 
mov e.., (dword )?\[(e..|e..\+0x[0-9]{1,8}|e..\+e..)\] 
mov (dword )?\[(e..|e..\+0x[0-9]{1,8}|e..\+e..)\], e.. 
mov e.., e.. 
(add|adc) e.., (e..| \[) 
sub e.., (e..| \[) 
inc e.. 
dec e.. 
(!xor|and) e.., e.. 
ret(n)?( 0x[0-9a-zA-Z]{1,8})? 
: int3
```