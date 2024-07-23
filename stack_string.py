from pwn import *
from prettytable import PrettyTable, PLAIN_COLUMNS
import argparse

def main(string, out_file, neg, full, encoding):

    eax = "eax"
    ax = "ax"
    al = "al"
    
    string = string.encode(encoding)
    
    pieces = []
    for i in range(0, len(string), 4):
        chunk = string[i : i + 4]
        pieces.append((hex(unpack(chunk, "all")), chunk.decode(encoding)))
        
    counter = 0
    new_line = '\n'
    if (out_file != ""): f = open(out_file, "w")
    
    x = PrettyTable()
    x.field_names = ["ASM", "Comments"]
    x.add_row([f"", f""])

    
    for each in pieces[::-1]:

        piece, value = each
        value = value[::-1]
        
        if len(piece) <= 10:
            register = eax
        
        if not full:     
            if len(piece) <= 8 and len(piece) > 6:
                x.add_row([f"xor {eax}, {eax}", f"; {eax} = 0"])
                if (out_file != ""): f.write(f"	xor {eax}, {eax}                  ; {eax} = 0")
                register = al
                piece1 = piece[:4]
                x.add_row([f"mov {register}, {piece1}", f"; Ensure NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	mov {register}, {piece1}                ; Ensure NULL byte")
                x.add_row([f"push {eax}", f"; Part of '{value}' string"])
                if (out_file != ""): f.write(f"{new_line}	push {eax}               ; Part of '{value}' string")
                register = ax
                piece2 = "0x" + piece[4:]
                x.add_row([f"mov {register}, {piece2}", f"; Ensure NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	mov {register}, {piece2}                ; Ensure NULL byte")
                x.add_row([f"push {register}", f"; Part of '{value}' string"])
                if (out_file != ""): f.write(f"{new_line}	push {register}               ; Part of '{value}' string")
                counter += 1
                continue
            
            if len(piece) <= 6 and len(piece) > 4:
                x.add_row([f"xor {eax}, {eax}", f"; {eax} = 0"])
                if (out_file != ""): f.write(f"	xor {eax}, {eax}                  ; {eax} = 0")
                register = ax
                x.add_row([f"mov {register}, {piece}", f"; Ensure NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	mov {register}, {piece}                ; Ensure NULL byte")
                x.add_row([f"push {eax}", f"; End of string '{value}' with NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	push {eax}                      ; End of string '{value}' with NULL byte")
                counter += 1
                continue
            
            if len(piece) <= 4:
                x.add_row([f"xor {eax}, {eax}", f"; {eax} = 0"])
                if (out_file != ""): f.write(f"	xor {eax}, {eax}                  ; {eax} = 0")
                register = al
                x.add_row([f"mov {register}, {piece}", f"; Ensure NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	mov {register}, {piece}                ; Ensure NULL byte")
                x.add_row([f"push {eax}", f"; End of string '{value}' with NULL byte"])
                if (out_file != ""): f.write(f"{new_line}	push {eax}                      ; End of string '{value}' with NULL byte")
                counter += 1
                continue
        
        if counter == 0:
            x.add_row([f"xor {eax}, {eax}", f"; {eax} = 0"])
            if (out_file != ""): f.write(f"	xor {eax}, {eax}                  ; {eax} = 0")
            x.add_row([f"push {eax}", f"; Ensure NULL byte"])
            if (out_file != ""): f.write(f"{new_line}	push {eax}                      ; Ensure NULL byte")

        if neg:
            hex_int_neg = hex((0 - int(f"{piece}", base = 16)) & (2**32-1))
            x.add_row(["",""])
            if (out_file != ""): f.write(f"	                                ;")
            x.add_row([f"mov edx, {hex_int_neg}", f"; '{value}' = {piece}"])
            if (out_file != ""): f.write(f"{new_line}{new_line}	mov edx, {hex_int_neg}           ; '{value}' = {piece}")
            x.add_row([f"neg edx", f"; 0 - {piece} = {hex_int_neg}"])
            if (out_file != ""): f.write(f"{new_line}	neg edx                       ; 0 - {piece} = {hex_int_neg}")
            x.add_row([f"push edx", f"; push {hex_int_neg}"])
            if (out_file != ""): f.write(f"{new_line}	push edx                      ; push {hex_int_neg}")
        else:
            x.add_row([f"push {piece}", f"; Push '{value}'"])
            if (out_file != ""): f.write(f"{new_line}	push {piece}               ; Push '{value}'")
        counter += 1
    
    x.align["ASM"] = "l"
    x.align["Comments"] = "l"
    x.set_style(PLAIN_COLUMNS)
    
    print("")
    print(x)
    print("")
    if (out_file != ""): f.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Push STRING in to the stack.")
    parser.add_argument("string", metavar='STRING', help="String to convert.")
    parser.add_argument("-o", "--output", action="store", default = "", help="Save output as <filename>.")
    parser.add_argument("-n", "--neg", action="store_true", help="Push string using negative values to avoid nullbytes.")
    parser.add_argument("-f", "--full", action="store_true", help="Use full 32-bit size regiser for the string.")
    parser.add_argument("-e", "--encoding", action="store", default = "utf-8", choices = ["utf-8", "utf-16-le"], help="Use specific encoding.")
    
    args = parser.parse_args()
    main(args.string, args.output, args.neg, args.full, args.encoding)