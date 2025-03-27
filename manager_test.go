package zerocert

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestManager_init(t *testing.T) {
	type fields struct {
		Email     string
		Reg       string
		Key       []byte
		Domain    string
		CacheFile string
		TLSConfig *tls.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr string
	}{
		{
			name:    "Test with empty fields",
			fields:  fields{},
			wantErr: "loading ACME key",
		},
		{
			name: "Test with valid fields",
			fields: fields{
				Email: "test@example.com",
				Reg:   "https://example.com/acme/reg",
				Key: []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBWesomdf9toRdcFXyXtSpbdMmZB83DtXQ+55mhjS6GRoAoGCCqGSM49
AwEHoUQDQgAEZH5K/qgG8c5nvZK0bJnzY9NZa/NdSAYy+YU7TOKbgHtYRlWofgI5
tswDaYyjs/HfTQW9kgnaZ7Hg+kD05ElrIe==
-----END EC PRIVATE KEY-----`),
				Domain:    "example.com",
				CacheFile: "cache.json",
				TLSConfig: &tls.Config{
					NextProtos: []string{"http/1.1"},
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				Email:     tt.fields.Email,
				Reg:       tt.fields.Reg,
				Key:       tt.fields.Key,
				Domain:    tt.fields.Domain,
				CacheFile: tt.fields.CacheFile,
				TLSConfig: tt.fields.TLSConfig,
			}
			if err := m.init(); (err != nil && tt.wantErr == "") || (tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Manager.init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
