// Package go-oui provides functions to work with MAC and OUI's
package ouidb

import (
        "bytes"
        "fmt"
        "os"
        "strconv"
        "regexp"
        "errors"
        "strings"
        "bufio"
)

// https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf
// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// Hexadecimal to integer starting at &s[i0].
// Returns number, new offset, success.
func xtoi(s string, i0 int) (n int, i int, ok bool) {
    n = 0
        for i = i0; i < len(s); i++ {
            if '0' <= s[i] && s[i] <= '9' {
                n *= 16
                    n += int(s[i] - '0')
            } else if 'a' <= s[i] && s[i] <= 'f' {
                n *= 16
                    n += int(s[i]-'a') + 10
            } else if 'A' <= s[i] && s[i] <= 'F' {
                n *= 16
                    n += int(s[i]-'A') + 10
            } else {
                break
            }
            if n >= big {
                return 0, i, false
            }
        }
    if i == i0 {
        return 0, i, false
    }
    return n, i, true
}

// xtoi2 converts the next two hex digits of s into a byte.
// If s is longer than 2 bytes then the third byte must be e.
// If the first two bytes of s are not hex digits or the third byte
// does not match e, false is returned.
func xtoi2(s string, e byte) (byte, bool) {
    if len(s) > 2 && s[2] != e {
        return 0, false
    }
    n, ei, ok := xtoi(s[:2], 0)
        return byte(n), ok && ei == 2
}

const hexDigit = "0123456789abcdef"

type HardwareAddr []byte

func (a HardwareAddr) String() string {
        if len(a) == 0 {
                return ""
        }
        buf := make([]byte, 0, len(a)*3-1)
        for i, b := range a {
                if i > 0 {
                        buf = append(buf, ':')
                }
                buf = append(buf, hexDigit[b>>4])
                buf = append(buf, hexDigit[b&0xF])
        }
        return string(buf)
}

// ParseMAC parses s as an IEEE 802 MAC-48, EUI-48, or EUI-64 using one of the
// following formats:
//   01:23:45:67:89:ab
//   01:23:45:67:89:ab:cd:ef
//   01-23-45-67-89-ab
//   01-23-45-67-89-ab-cd-ef
//   0123.4567.89ab
//   0123.4567.89ab.cdef
func ParseOUI(s string, size int) (hw HardwareAddr, err error) {
        if s[2] == ':' || s[2] == '-' {
                if (len(s)+1)%3 != 0 {
                        goto error
                }

                n := (len(s) + 1) / 3

                hw = make(HardwareAddr, size)
                for x, i := 0, 0; i < n; i++ {
                        var ok bool
                        if hw[i], ok = xtoi2(s[x:], s[2]); !ok {
                                goto error
                        }
                        x += 3
                }
        } else {
                goto error
        }
        return hw, nil

error:
        return nil, errors.New("invalid MAC address: " + s)
}

// ParseMAC parses s as an IEEE 802 MAC-48, EUI-48, or EUI-64 using one of the
// following formats:
//   01:23:45:67:89:ab
//   01:23:45:67:89:ab:cd:ef
//   01-23-45-67-89-ab
//   01-23-45-67-89-ab-cd-ef
//   0123.4567.89ab
//   0123.4567.89ab.cdef
func ParseMAC(s string) (hw HardwareAddr, err error) {
        if len(s) < 14 {
                goto error
        }

        if s[2] == ':' || s[2] == '-' {
                if (len(s)+1)%3 != 0 {
                        goto error
                }
                n := (len(s) + 1) / 3

                hw = make(HardwareAddr, n)
                for x, i := 0, 0; i < n; i++ {
                        var ok bool
                        if hw[i], ok = xtoi2(s[x:], s[2]); !ok {
                                goto error
                        }
                        x += 3
                }
        } else if s[4] == '.' {
                if (len(s)+1)%5 != 0 {
                        goto error
                }
                n := 2 * (len(s) + 1) / 5
                if n != 6 && n != 8 {
                        goto error
                }
                hw = make(HardwareAddr, n)
                for x, i := 0, 0; i < n; i += 2 {
                        var ok bool
                        if hw[i], ok = xtoi2(s[x:x+2], 0); !ok {
                                goto error
                        }
                        if hw[i+1], ok = xtoi2(s[x+2:], s[4]); !ok {
                                goto error
                        }
                        x += 5
                }
        } else {
                goto error
        }
        return hw, nil

error:
        return nil, errors.New("invalid MAC address: " + s)
}

// Mask returns the result of masking the address with mask.
func (address HardwareAddr) Mask(mask []byte) []byte {
        n := len(address)
        if n != len(mask) { 
                return nil
        }
        out := make([]byte, n)
        for i := 0; i < n; i++ {
                out[i] = address[i] & mask[i]
        }
        return out
}


type t2 struct {
    T3 map[byte]t2
    Block *AddressBlock
}

type OuiDb struct {
    hw [6]byte
    mask int

    dict [][]byte
    Blocks []AddressBlock
    
    t map[int]t2
    Test t2
}

// Lookup finds the OUI the address belongs to
func (m *OuiDb) Lookup(address HardwareAddr ) *AddressBlock { 
    for _, block := range m.Blocks {
        if (block.Contains(address)) {
            return &block
        }
    }

    return nil
}

func byteIndex(s string, c byte) int {
    for i := 0; i < len(s); i++ {
       if s[i] == c {
           return i
       }
   }
   return -1
}

func (m *OuiDb) Load(path string ) error { 
    file, err := os.Open(path)
    if err!=nil {
        return (err)
    }

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if (len(scanner.Text())==0 || scanner.Text()[0]=='#') {
            continue
        }

        re := regexp.MustCompile(`((?:(?:[0-9a-zA-Z]{2})[-:]){2,5}(?:[0-9a-zA-Z]{2}))(?:/(\w{1,2}))?`)
        arr:=strings.Split(scanner.Text(), "\t")

        matches:=re.FindAllStringSubmatch(arr[0], -1)
        if len(matches) == 0 {
            continue
        }

        block := AddressBlock{}

        s := matches[0][1]

        i := byteIndex(s, '/')
        
        if (i==-1) {
            block.Oui, err = ParseOUI(s, 6)
            block.Mask = 24 // len(block.Oui) * 8
        } else {
            block.Oui, err = ParseOUI(s[:i], 6)
            block.Mask, err = strconv.Atoi(s[i+1:])
        }

        fmt.Println("OUI:", block.Oui, block.Mask, err)

        block.Organization = arr[1]
        m.Blocks = append (m.Blocks, block)

        // create smart map
        for i := len(block.Oui) - 1; i >= 0; i-- {
            _ = block.Oui[i]
            
        }

        // fmt.Printf("BLA %v %v ALB", m.hw, m.mask)
    }

    if err := scanner.Err(); err != nil {
        return (err);
    } 

    return (nil)
}

func CIDRMask(ones, bits int) []byte {
    l := bits / 8
    m := make([]byte, l)

    n := uint(ones)
    for i := 0; i < l; i++ {
            if n >= 8 {
                    m[i] = 0xff
                    n -= 8
                    continue
            }
            m[i] = ^byte(0xff >> n)
            n = 0
    }

    return (m)
}

// oui, mask, organization
type AddressBlock struct {
    Oui HardwareAddr
    Mask int
    Organization string
}

// Contains reports whether the mac address belongs to the OUI
func (b *AddressBlock) Contains(address HardwareAddr ) bool { 
    fmt.Println("%v %v %v %v", b.Oui, len(b.Oui), address.Mask(CIDRMask(b.Mask, len(b.Oui)*8)), CIDRMask(b.Mask, len(b.Oui)*8))

    return (bytes.Equal(address.Mask(CIDRMask(b.Mask, len(b.Oui)*8)), b.Oui)) 
}

