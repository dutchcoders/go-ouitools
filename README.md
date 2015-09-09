go-ouitools
===========

Golang tools to work with Mac addresses and oui. Includes oui database to resolve to vendor. 

## Sample
```
package main

import (
  "fmt"
	"github.com/dutchcoders/go-ouitools"
)

var db *OuiDb

func main() {
	db := New("oui.txt")
	if db == nil {
		t.Fatal("database not initialized")
	}
  
  mac:="00:16:e0:3d:f4:4c"
	v, err := db.VendorLookup(mac)
	if err != nil {
		fmt.Fatalf("parse: %s: %s", mac, err.Error())
	}
	
	fmt.Printf("%s => %s\n", mac, v)
}

```

## Testing
```
go test
```

## References
* wireshark oui database

## Contributors
* Remco Verhoef (Dutchcoders) @remco_verhoef
* Claudio Matsuoka
