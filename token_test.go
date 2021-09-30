package splittoken_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/iterate/splittoken"
)

func TestNewToken(t *testing.T) {
	id := uuid.New()
	bs := make([]byte, 24)
	if _, err := rand.Read(bs); err != nil {
		t.Fatalf("reading bytes: %v", err)
	}
	tk, err := splittoken.NewToken("test", id, bs)
	if err != nil {
		t.Fatalf("NewToken() returned err %v", err)
	}
	if s := tk.Serial(); s != id {
		t.Errorf("tk.Serial() = %s; want %s", s, id)
	}
	if s := tk.Secret(); !bytes.Equal(s, bs) {
		t.Errorf("tk.Secret() = %x; want %x", s, bs)
	}

	if err := splittoken.Verify(tk); err != nil {
		t.Errorf("got invalid token: %v", err)
	}
}


func ExampleNewToken() {
	usage := "myu"
	id, err := uuid.Parse("123c3af9-6eac-4392-b673-481cfe3c6d6d")
	if err != nil {
		log.Fatal(err)
	}
	secret := []byte("autogenerated secret")
	tk, err := splittoken.NewToken(usage, id, secret)
	if err != nil {
		log.Fatal(err)
	}

	// Output:
	// Token: myu_1X2QxxKglFic3TYI90p9zF7979gWIltsjQ9t2PJCaEK8WjBBt9XaZ8
	fmt.Printf("Token: %s", tk)
}

func ExampleVerify() {
	// this has an invalid bit in the checksum
	token := splittoken.Token("myu_1X2QxxKglFic3TYI90p9zF7979gWIltsjQ9t2PJCaEK8WjBBt9XaZ9")

	err := splittoken.Verify(token)
	// Output:
	// Validate result: invalid checksum
	fmt.Printf("Validate result: %s", err)
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		tk    splittoken.Token
		wantErr error
	}{
		{"Valid", "myu_1X2QxxKglFic3TYI90p9zF7979gWIltsjQ9t2PJCaEK8WjBBt9XaZ8", nil},
		{"Invalid checksum", "myu_1X2QxxKglFic3TYI90p9zF7979gWIltsjQ9t2PJCaEK8WjBBt9XaZ9", splittoken.ErrInvalidChecksum},
		{"Invalid syntax", "myu.1X2QxxKglFic3TYI90p9zF7979gWIltsjQ9t2PJCaEK8WjBBt9XaZ8", splittoken.ErrInvalidSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := splittoken.Verify(tt.tk); !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}