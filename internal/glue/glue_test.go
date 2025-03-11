package glue

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestRetreiveIPs(t *testing.T) {
	tests := []struct {
		fqdn    string
		want    []net.IP
		wantErr bool
	}{
		{"ssic.dev", []net.IP{net.ParseIP("157.230.89.195")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			got, err := RetreiveIPs(context.TODO(), tt.fqdn)
			if (err != nil) != tt.wantErr {
				t.Errorf("RetreiveGlueIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RetreiveGlueIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}
