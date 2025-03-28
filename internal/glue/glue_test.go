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
		{"r.ssic.dev", []net.IP{
			net.ParseIP("162.243.171.171"),
			net.ParseIP("137.184.234.251"),
			net.ParseIP("46.101.237.176")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			var gc Client
			got, err := gc.RetreiveIPs(context.TODO(), tt.fqdn)
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
