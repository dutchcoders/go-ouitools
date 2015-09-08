// Package go-oui provides functions to work with MAC and OUI's
package ouidb

import (
	"fmt"
	"log"
	"testing"
)

func Test(*testing.T) {
	d := &OuiDb{}
	err := d.Load("oui.txt")

	if err != nil {
		log.Fatal("Error %v", err)
	}

	address, _ := ParseMAC("60:03:08:a0:ec:a6")
	block := d.Lookup(address)

	fmt.Println("bla %v", block)

	address, _ = ParseMAC("00:25:9c:42:c2:62")
	block = d.Lookup(address)

	fmt.Println("Bla %v", block)

	address, _ = ParseMAC("00:16:e0:3d:f4:4c")
	block = d.Lookup(address)

	fmt.Println("Bla %v", block)

}
