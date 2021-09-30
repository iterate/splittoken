//go:build go1.18

package splittoken_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/iterate/splittoken"
)

func FuzzNewToken(f *testing.F) {
	namespaceTesting := uuid.Must(uuid.Parse("2034963f-6992-4349-9dcd-91178ddbf7c5"))
	f.Fuzz(func(t *testing.T, usage string, idSeed string, secret []byte) {
		id := uuid.NewSHA1(namespaceTesting, []byte(idSeed))
		tk, err := splittoken.New(usage, id, secret)
		if err != nil {
			t.Skip()
		}
		if s := tk.Serial(); s != id {
			t.Errorf("tk.Serial() = %s; want %s", s, id)
		}
		if s := tk.Secret(); !bytes.Equal(s, secret) {
			t.Errorf("tk.Secret() = %x; want %x", s, secret)
		}
		if err := splittoken.Verify(tk); err != nil {
			t.Errorf("got invalid token: %v", err)
		}
	})
}
