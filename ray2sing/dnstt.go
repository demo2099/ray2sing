package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func DnsttSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	d := &T.DnsttOptions{
		DialerOptions: getDialerOptions(decoded),
		PublicKey:     getOneOfN(decoded, "", "pubkey", "publickey", "serverpublickey"),
		Domain:        getOneOfN(decoded, "", "domain", "serveraddress", "address"),
		Resolvers:     strings.Split(getOneOfN(decoded, "", "resolver"), ","),
	}
	return &T.Outbound{
		Tag:     u.Name + "§hide§",
		Type:    "dnstt",
		Options: d,
	}, nil
}