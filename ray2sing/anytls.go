package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func AnyTLSSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	tlsOpts := getTLSOptions(decoded)

	if tlsOpts.TLS != nil && decoded["security"] == "reality" {
		tlsOpts.TLS.Reality = &T.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: decoded["pbk"],
			ShortID:   decoded["sid"],
		}
	}

	password := u.Username
	if password == "" {
		password = u.Password
	}

	out := &T.Outbound{
		Tag:  u.Name,
		Type: "anytls",
		Options: &T.AnyTLSOutboundOptions{
			ServerOptions:               u.GetServerOption(),
			Password:                    password,
			OutboundTLSOptionsContainer: tlsOpts,
		},
	}

	return out, nil
}
