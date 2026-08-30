package ray2sing

import (
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	// WARP not available in sing-box v4.1.0, fallback to WireGuard
	allowedIPs := func() badoption.Listable[netip.Prefix] {
		raw := getOneOfN(u.Params, "", "allowedips", "localaddress")
		var out []netip.Prefix
		for _, s := range strings.Split(raw, ",") {
			if s != "" {
				p, _ := netip.ParsePrefix(strings.TrimSpace(s))
				if p.IsValid() {
					out = append(out, p)
				}
			}
		}
		if len(out) == 0 {
			out = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		}
		return badoption.Listable[netip.Prefix](out)
	}()

	wgopts := T.WireGuardEndpointOptions{
		PrivateKey: u.Username,
		Peers: []T.WireGuardPeer{
			T.WireGuardPeer{
				Address:                     u.Hostname,
				Port:                        u.Port,
				PublicKey:                   getOneOfN(u.Params, "", "publickey", "peerpublickey", "pub"),
				PreSharedKey:                getOneOfN(u.Params, "", "presharedkey", "psk"),
				AllowedIPs:                  allowedIPs,
				PersistentKeepaliveInterval: func() uint16 { v, _ := strconv.Atoi(getOneOfN(u.Params, "", "keepalive")); return uint16(v) }(),
			},
		},
		MTU:   uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		Noise: getWireGuardNoise(u.Params, false),
	}
	if reservedStr, ok := u.Params["reserved"]; ok {
		reservedParts := strings.Split(reservedStr, ",")
		for _, part := range reservedParts {
			num, err := strconv.ParseUint(part, 10, 8)
			if err == nil {
				wgopts.Peers[0].Reserved = append(wgopts.Peers[0].Reserved, uint8(num))
			}
		}
	}
	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			wgopts.Workers = workers
		}
	}

	out := &T.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     u.Name,
		Options: &wgopts,
	}
	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return out, nil
}