// Package go-oui provides functions to work with MAC and OUI's
package ouidb

import (
	"testing"
)

var db *OuiDb

func lookup(t *testing.T, mac, org string) {
	if db == nil {
		t.Fatal("database not initialized")
	}
	v, err := db.VendorLookup(mac)
	if err != nil {
		t.Fatalf("parse: %s: %s", mac, err.Error())
	}
	if v != org {
		t.Fatalf("lookup: input %s, expect %s, got %s", mac, org, v)
	}
	t.Logf("%s => %s\n", mac, v)
}

func TestInitialization(t *testing.T) {
	db = New("oui.txt")
	if db == nil {
		t.Fatal("can't load database file oui.txt")
	}
}

func TestMissingDBFile(t *testing.T) {
	db := New("bad-file")
	if db != nil {
		t.Fatal("didn't return nil on missing file")
	}
}

func TestInvalidDBFile(t *testing.T) {
	db := New("ouidb_test.go")
	if db != nil {
		t.Fatal("didn't return nil on bad file")
	}
}

func TestLookup1(t *testing.T) {
	lookup(t, "60:03:08:a0:ec:a6", "Apple, Inc.")
}

func TestLookup2(t *testing.T) {
	lookup(t, "00:25:9c:42:c2:62", "Cisco-Linksys, LLC")
}

func TestLookup3(t *testing.T) {
	lookup(t, "00:16:e0:3d:f4:4c", "3Com Ltd")
}
