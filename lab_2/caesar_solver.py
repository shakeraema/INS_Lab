import string

CIPHER = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

ALPH = string.ascii_lowercase  #string.ascii_lowercase is "abcdefghijklmnopqrstuvwxyz". I put that into ALPH so I can index into it and find letter positions.
def shift_decode(s, k):      #define a function named shift_decode with two inputs: s="the text to decode (a string)" and k="the shift amount (an integer)".
    out = []                  #create an empty list named out to store the decoded characters.
    for ch in s:          #for each character ch in the input string s:
        if ch in ALPH:
            out.append(ALPH[(ALPH.index(ch) - k) % 26]) #if ch is a lowercase letter (i.e., it is in ALPH), find its index in ALPH, subtract k from that index to decode it, and use modulo 26 to wrap around if necessary. Append the decoded character to the out list.
        else:
            out.append(ch)
    return "".join(out)

# Try all 26 shifts and print all
for k in range(26):
    cand = shift_decode(CIPHER, k)
    print(f"{k:2d} -> {cand}")
