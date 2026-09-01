package ray2sing

//based on https://github.com/XTLS/Xray-core/issues/91
//todo merge with https://github.com/XTLS/libXray/
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/miekg/dns"
)

const USER_AGENT string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

type ParserFunc func(string) (*option.Outbound, error)
type EndpointParserFunc func(string) (*T.Endpoint, error)

// splitECHParam recognises the v2rayN/v2rayNG ECH parameter form
// "<ech-domain>+https://<doh-url>" and splits it into its two halves.
//
// The separator is accepted as a literal "+", as a plain space (share links are
// often copied through layers that apply HTML form decoding, which rewrites "+"
// as a space) and as "%2B" for double-encoded links. Accepting all three keeps
// ECH working no matter which client produced or relayed the link.
func splitECHParam(echParam string) (echDomain string, dohURL string, ok bool) {
	for _, sep := range []string{"+https://", " https://", "%2Bhttps://"} {
		idx := strings.Index(echParam, sep)
		if idx < 0 {
			continue
		}
		echDomain = strings.TrimSpace(echParam[:idx])
		tail := echParam[idx:]
		dohURL = tail[strings.Index(tail, "https://"):]
		if echDomain == "" || dohURL == "" {
			continue
		}
		return echDomain, dohURL, true
	}
	return "", "", false
}

// fetchECHConfigFromDoH queries a DoH server for HTTPS records and extracts the
// ECH configlist, returned as a PEM block together with the record TTL in
// seconds.
//
// Returns "" on any failure. The caller is then expected to leave the ECH config
// empty so sing-box resolves it itself through its own DNS router.
func fetchECHConfigFromDoH(echDomain string, dohURL string) (configPEM string, ttl uint32) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, false)
			writeCrashLog("fetchECHConfigFromDoH", fmt.Sprintf("%v", r), buf[:n])
			configPEM, ttl = "", 0
		}
	}()
	if !strings.HasPrefix(dohURL, "https://") {
		dohURL = "https://" + dohURL
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(echDomain), dns.TypeHTTPS)
	msg.RecursionDesired = true

	data, err := msg.Pack()
	if err != nil {
		fmt.Printf("[ray2sing] ECH: dns pack error: %v\n", err)
		return "", 0
	}

	client := &http.Client{Timeout: echDoHTimeout}
	resp, err := client.Post(dohURL, "application/dns-message", bytes.NewReader(data))
	if err != nil {
		fmt.Printf("[ray2sing] ECH: DoH request to %s failed: %v\n", dohURL, err)
		return "", 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[ray2sing] ECH: DoH %s returned status %d\n", dohURL, resp.StatusCode)
		return "", 0
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ray2sing] ECH: DoH read error: %v\n", err)
		return "", 0
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respData); err != nil {
		fmt.Printf("[ray2sing] ECH: dns unpack error: %v\n", err)
		return "", 0
	}
	if respMsg.Rcode != dns.RcodeSuccess {
		fmt.Printf("[ray2sing] ECH: DoH rcode %d for %s\n", respMsg.Rcode, echDomain)
		return "", 0
	}

	for _, answer := range respMsg.Answer {
		httpsRec, isHTTPS := answer.(*dns.HTTPS)
		if !isHTTPS {
			continue
		}
		for _, param := range httpsRec.Value {
			echValue, isECH := param.(*dns.SVCBECHConfig)
			if !isECH {
				continue
			}
		b64 := base64.StdEncoding.EncodeToString(echValue.ECH)
		configPEM = "-----BEGIN ECH CONFIGS-----\n"
			for i := 0; i < len(b64); i += 64 {
				end := i + 64
				if end > len(b64) {
					end = len(b64)
				}
				configPEM += b64[i:end] + "\n"
			}
			configPEM += "-----END ECH CONFIGS-----"
			fmt.Printf("[ray2sing] ECH: got %d byte configlist for %s\n", len(echValue.ECH), echDomain)
			return configPEM, httpsRec.Hdr.Ttl
		}
	}
	fmt.Printf("[ray2sing] ECH: no ech value in HTTPS record for %s\n", echDomain)
	return "", 0
}

const (
	// Two short attempts beat one long one: config parsing blocks on this, and
	// a single lost packet should not cost a profile its ECH config list.
	echDoHTimeout    = 2 * time.Second
	echDoHAttempts   = 2
	echDoHRetryDelay = 250 * time.Millisecond

	// A lookup that fails while the cache is empty is only remembered briefly,
	// so the next parse can try again instead of being pinned to "no ECH".
	echNegativeTTL = 10 * time.Second
	echMinimumTTL  = 60 * time.Second
	echMaximumTTL  = 3600 * time.Second
)

// ECH configlists rotate rarely, but getTLSOptions runs for every outbound on
// every config parse. Without a cache, a subscription holding a handful of ECH
// nodes pays a DoH round trip (up to echDoHTimeout each) every single time the
// profile is rebuilt.
var (
	echCacheLock   sync.Mutex
	echCacheValues = make(map[string]echCacheEntry)
)

type echCacheEntry struct {
	configPEM  string
	expires    time.Time
	refreshing bool
}

// cachedECHConfigFromDoH returns the ECH config list for this domain and DoH
// server, hitting the network only when the entry is missing or stale.
//
// The important property is that a failed refresh never costs the outbound a
// config list it already holds. ECH config lists rotate on the order of days,
// and a stale one is repaired by sing-box itself: the server answers an ECH
// rejection with a retry config list and the handshake is redone with it. So on
// failure we keep serving the previous value and refresh in the background,
// rather than dropping to an empty config and leaving the node unconnectable
// for as long as the DoH server stays unhappy.
// cachedECHConfigFromDoH is the synchronous entry point called during config
// parsing (i.e. when a profile is enabled). Because it runs on the main path,
// an unrecovered panic here would abort the whole in-process gomobile core and
// flash-close the app — the classic "enable node → app vanishes" crash. Wrap
// the body so any panic degrades to "no ECH config" instead of killing the
// process. This mirrors the recover() guard already present in
// fetchECHConfigFromDoH and backgroundECHRefresh.
func cachedECHConfigFromDoH(echDomain string, dohURL string) (ret string) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, false)
			writeCrashLog("cachedECHConfigFromDoH", fmt.Sprintf("%v", r), buf[:n])
			ret = ""
		}
	}()
	key := echDomain + "|" + dohURL
	now := time.Now()

	echCacheLock.Lock()
	entry, found := echCacheValues[key]
	echCacheLock.Unlock()

	if found && now.Before(entry.expires) {
		return entry.configPEM
	}

	configPEM, ttl := fetchECHConfigWithRetry(echDomain, dohURL)

	echCacheLock.Lock()
	defer echCacheLock.Unlock()

	// Re-read: another parse may have refreshed the entry while we were away.
	entry, found = echCacheValues[key]
	if configPEM != "" {
		echCacheValues[key] = echCacheEntry{configPEM: configPEM, expires: now.Add(clampECHTTL(ttl))}
		return configPEM
	}
	if found && entry.configPEM != "" {
		if !entry.refreshing {
			entry.refreshing = true
			// Extend so the stale value is not re-fetched on every parse while
			// the background refresh is still in flight.
			entry.expires = now.Add(echMinimumTTL)
			echCacheValues[key] = entry
			go backgroundECHRefresh(key, echDomain, dohURL)
		}
		return entry.configPEM
	}
	echCacheValues[key] = echCacheEntry{configPEM: "", expires: now.Add(echNegativeTTL)}
	return ""
}

// backgroundECHRefresh retries a lookup that failed while a usable value was
// still cached, so the next parse does not have to pay for it.
//
// This runs as a bare background goroutine spawned from cachedECHConfigFromDoH.
// An unrecovered panic here kills the whole in-process gomobile core with no
// tombstone — the classic intermittent "enable node → app vanishes" crash — so
// the entire body is wrapped in recover(). On any panic we just leave the
// cached entry as-is (the defer in fetchECHConfigFromDoH already returns ""),
// which is the safe failure mode: a stale-but-usable ECH config beats none.
func backgroundECHRefresh(key string, echDomain string, dohURL string) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, false)
			writeCrashLog("backgroundECHRefresh", fmt.Sprintf("%v", r), buf[:n])
		}
	}()
	configPEM, ttl := fetchECHConfigWithRetry(echDomain, dohURL)
	now := time.Now()

	echCacheLock.Lock()
	defer echCacheLock.Unlock()

	entry := echCacheValues[key]
	entry.refreshing = false
	if configPEM != "" {
		entry.configPEM = configPEM
		entry.expires = now.Add(clampECHTTL(ttl))
	} else if entry.configPEM == "" {
		entry.expires = now.Add(echNegativeTTL)
	}
	// A failed refresh of a value we still hold leaves that value in place and
	// clears the flag, so a later parse can try again.
	echCacheValues[key] = entry
}

func fetchECHConfigWithRetry(echDomain string, dohURL string) (string, uint32) {
	var configPEM string
	var ttl uint32
	for attempt := 0; attempt < echDoHAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(echDoHRetryDelay)
		}
		configPEM, ttl = fetchECHConfigFromDoH(echDomain, dohURL)
		if configPEM != "" {
			return configPEM, ttl
		}
	}
	return "", 0
}

func clampECHTTL(ttl uint32) time.Duration {
	cacheTTL := time.Duration(ttl) * time.Second
	switch {
	case cacheTTL < echMinimumTTL:
		return echMinimumTTL
	case cacheTTL > echMaximumTTL:
		return echMaximumTTL
	}
	return cacheTTL
}

func getTLSOptions(decoded map[string]string) T.OutboundTLSOptionsContainer {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return T.OutboundTLSOptionsContainer{TLS: nil}
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *option.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	// Reality and ECH are mutually exclusive and sing-box rejects the combination
	// outright. The callers assign Reality after this function returns, so the
	// conflict can only be avoided here.
	if hasECH && decoded["security"] == "reality" {
		fmt.Printf("[ray2sing] ECH: ignored for node, reality already in use\n")
	} else if hasECH {
		ECHOpts = &option.OutboundECHOptions{
			Enabled: true,
		}
		valECH = strings.TrimSpace(valECH)
		if len(valECH) > 5 {
			// The synchronous ECH resolution below runs on the main config
			// parse path (i.e. when a profile is enabled). Wrap it so any panic
			// degrades to "no ECH config" instead of aborting the in-process
			// gomobile core and flash-closing the app. This mirrors the recover()
			// guards already present in fetchECHConfigFromDoH,
			// cachedECHConfigFromDoH and backgroundECHRefresh.
			func() {
				defer func() {
					if r := recover(); r != nil {
						buf := make([]byte, 1<<20)
						n := runtime.Stack(buf, false)
						writeCrashLog("getTLSOptions.ECH", fmt.Sprintf("%v", r), buf[:n])
						// Graceful degradation: drop ECH for this node so the
						// outbound still connects via sing-box's own DNS router.
						ECHOpts = nil
					}
				}()
				var echConfigPEM string
				// v2rayN/v2rayNG format: "<ech-domain>+https://<doh-url>".
				// Anything else is treated as an inline (base64) ECH configlist.
				if domain, dohURL, isDoH := splitECHParam(valECH); isDoH {
					// Tell sing-box which name publishes the config list even when
					// the prefetch below comes back empty. Otherwise its own DNS
					// lookup falls back to the SNI, which is not necessarily the
					// name carrying the ECH record.
					ECHOpts.QueryServerName = domain
					echConfigPEM = cachedECHConfigFromDoH(domain, dohURL)
				} else {
					echConfigPEM = valECH
				}
				if echConfigPEM != "" {
					if !strings.Contains(echConfigPEM, "-----BEGIN ECH CONFIGS-----") {
						echConfigPEM = "-----BEGIN ECH CONFIGS-----\n" + echConfigPEM + "\n-----END ECH CONFIGS-----"
					}
					// sing-box hard-fails the outbound on a malformed PEM
					// ("invalid ECH configs pem"), which would make the node
					// unreachable. Drop the config instead and let sing-box resolve
					// ECH itself through its DNS router.
					if block, rest := pem.Decode([]byte(echConfigPEM)); block != nil && block.Type == "ECH CONFIGS" && len(rest) == 0 {
						ECHOpts.Config = badoption.Listable[string]{echConfigPEM}
					} else {
						fmt.Printf("[ray2sing] ECH: malformed config for node, falling back to sing-box DNS lookup\n")
					}
				}
			}()
		}
	}

	fp := decoded["fp"]
	if fp == "" && decoded["security"] == "reality" {
		fp = "chrome"
	}
	insecure, err := getOneOf(decoded, "insecure", "allowinsecure")
	if err != nil {
		insecure = "false"
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure == "true" || insecure == "1",
		DisableSNI: getOneOfN(decoded, "", "nosni") != "",
		ECH:        ECHOpts,
		// TLSTricks:  getTricksOptions(decoded),
	}
	if fp != "" && !tlsOptions.DisableSNI {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		net := getOneOfN(decoded, "net")
		if net == "" {
			net = getOneOfN(decoded, "type")
		}
		if net == "httpupgrade" || net == "ws" || net == "grpc" || net == "h2" {
			tlsOptions.ALPN = []string{"h2", "http/1.1"}
		} else {
			tlsOptions.ALPN = strings.Split(alpn, ",")
			if getALPNversion(tlsOptions.ALPN) == 3 && getOneOfN(decoded, "", "type") == "xhttp" || getOneOfN(decoded, "", "net") == "xhttp" {
				tlsOptions.UTLS = nil //TODO utls quic has bug
			}
		}

	}
	return T.OutboundTLSOptionsContainer{
		TLS: tlsOptions,
	}

}

func getTricksOptions(decoded map[string]string) *option.TLSTricksOptions {
	trick := option.TLSTricksOptions{}
	if decoded["mc"] == "1" {
		trick.MixedCaseSNI = true
	}
	trick.PaddingMode = decoded["padmode"]
	trick.PaddingSNI = decoded["padsni"]
	trick.PaddingSize = decoded["padsize"]

	if !trick.MixedCaseSNI && trick.PaddingMode == "" && trick.PaddingSNI == "" && trick.PaddingSize == "" {
		return nil
	}
	return &trick
}
func getFragmentOptions(decoded map[string]string) option.TLSFragmentOptions {
	trick := option.TLSFragmentOptions{}
	fragment := decoded["fragment"]
	if fragment != "" {
		splt := strings.Split(fragment, ",")
		if len(splt) > 2 {
			if splt[0] == "tlshello" {
				trick.Size = splt[1]
				trick.Sleep = splt[2]
			} else {
				trick.Size = splt[0]
				trick.Sleep = splt[1]
			}
		}
	} else {
		trick.Size = decoded["fgsize"]
		trick.Sleep = decoded["fgsleep"]
	}
	if trick.Size != "" {
		trick.Enabled = true
	} else {
		trick.Enabled = false
	}

	return trick
}
func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["muxtype"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["muxmaxc"])
	// mux.MinStreams = toInt(decoded["muxsmin"])
	mux.MaxStreams = toInt(decoded["muxsmax"])
	mux.MinStreams = toInt(decoded["mux"])
	mux.Padding = decoded["muxpad"] == "true"

	if decoded["muxup"] != "" && decoded["muxdown"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["muxup"]),
			DownMbps: toInt(decoded["muxdown"]),
		}
	}
	return &mux
}
func getTransportOptions(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	var transportOptions option.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["servicename"]
	}
	if net == "raw" || net == "" {
		net = "tcp"
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
		net = "http"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		if decoded["security"] != "tls" {
			transportOptions.HTTPOptions.Method = "GET"
		}
		if host != "" {
			transportOptions.HTTPOptions.Host = badoption.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
	case "httpupgrade":
		decoded["alpn"] = "http/1.1"
		transportOptions.Type = C.V2RayTransportTypeHTTPUpgrade
		if host != "" {
			transportOptions.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			// pathQuery := pathURL.Query()
			// transportOptions.HTTPUpgradeOptions.MaxEarlyData = 0
			// transportOptions.HTTPUpgradeOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			// maxEarlyDataString := pathQuery.Get("ed")
			// if maxEarlyDataString != "" {
			// 	maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
			// 	if err == nil {
			// 		// transportOptions.HTTPUpgradeOptions.MaxEarlyData = uint32(maxEarlyDate)
			// 		pathQuery.Del("ed")
			// 		pathURL.RawQuery = pathQuery.Encode()
			// 	}
			// }
			transportOptions.HTTPUpgradeOptions.Path = pathURL.String()
		}
	case "ws":
		decoded["alpn"] = "http/1.1"

		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			pathQuery := pathURL.Query()
			transportOptions.WebsocketOptions.MaxEarlyData = 0
			transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		decoded["alpn"] = "h2"
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         badoption.Duration(15 * time.Second),
			PingTimeout:         badoption.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		decoded["alpn"] = "h3"
		transportOptions.Type = C.V2RayTransportTypeQUIC

	case "xhttp":
		transportOptions.Type = C.V2RayTransportTypeXHTTP
		transportOptions.XHTTPOptions = option.V2RayXHTTPOptions{
			Mode: getOneOfN(decoded, "auto", "mode"),
			V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
				Host: host,
				Path: path,
			},
		}

		if extra, ok := decoded["extra"]; ok {
			x := XHTTPExtra{}
			err := json.Unmarshal([]byte(extra), &x)
			if err != nil {
				return nil, err
			}
			transportOptions.XHTTPOptions.V2RayXHTTPBaseOptions = x.V2RayXHTTPBaseOptions
			if transportOptions.XHTTPOptions.Host == "" {
				transportOptions.XHTTPOptions.Host = host
			}
			if transportOptions.XHTTPOptions.Path == "" {
				transportOptions.XHTTPOptions.Path = path
			}
			if dl := x.DownloadSettings; dl != nil {
				transportOptions.XHTTPOptions.Download = &option.V2RayXHTTPDownloadOptions{
					V2RayXHTTPBaseOptions: dl.V2RayXHTTPBaseOptions,
					ServerOptions: option.ServerOptions{
						Server:     dl.Address,
						ServerPort: uint16(dl.Port),
					},
				}
				if transportOptions.XHTTPOptions.Download.Path == "" {
					transportOptions.XHTTPOptions.Download.Path = path
				}
				if dl.Security == "tls" && dl.TLSSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled:    true,
						ALPN:       dl.TLSSettings.ALPN,
						Insecure:   dl.TLSSettings.Insecure,
						ServerName: dl.TLSSettings.ServerName,
					}

					if dl.TLSSettings.Fingerprint != "" && getALPNversion(dl.TLSSettings.ALPN) != 3 {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.TLSSettings.Fingerprint,
						}
					}
				}
				if dl.Security == "reality" && dl.REALITYSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled: true,
						Reality: &option.OutboundRealityOptions{
							Enabled:   true,
							PublicKey: dl.REALITYSettings.PublicKey,
							ShortID:   dl.REALITYSettings.ShortId,
						},
						ServerName: dl.REALITYSettings.ServerName,
					}
					if dl.REALITYSettings.Fingerprint != "" {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.REALITYSettings.Fingerprint,
						}
					}
				}

			}

		}

		// 	var extraConfig option.V2RayXHTTPBaseOptions
		// 	err := json.Unmarshal([]byte(extra), &extraConfig)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	if headers, ok := extraConfig["headers"]; ok {
		// 		if headersMap, ok := headers.(map[string]string); ok {
		// 			transportOptions.XHTTPOptions.Headers = make(badoption.HTTPHeader, len(headersMap))
		// 			for k, v := range headersMap {
		// 				transportOptions.XHTTPOptions.Headers[k] = badoption.Listable[string]{v}
		// 			}
		// 		}
		// 	}
		// 	if dlsettings, ok := extraConfig["downloadSettings"]; ok {
		// 		if dlsettingsMap, ok := dlsettings.(map[string]any); ok {
		// 			if addr, ok := dlsettingsMap["address"]; ok {
		// 				if addrs, ok := addr.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServer = addrs
		// 				}
		// 			}
		// 			if port, ok := dlsettingsMap["port"]; ok {
		// 				if portInt, ok := port.(int); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = uint16(portInt)
		// 				} else if portuInt, ok := port.(uint16); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = portuInt
		// 				} else if ports, ok := port.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = toUInt16(ports, 0)
		// 				}
		// 			}

		// 		}
		// 	}
		// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
		// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noGRPCHeaderb
		// 		}
		// 	}
		// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
		// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noSSEHeaderb
		// 		}
		// 	}

		// 	if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
		// 		if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
		// 			transportOptions.XHTTPOptions.MaxEachPostBytes = uint64(scMaxBufferedPosti)
		// 		}
		// 	}

		// res["extra"] = extraConfig
		// }

	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getALPNversion(s []string) int {
	if len(s) == 0 {
		return 1
	}
	if s[0] == "h3" {
		return 3
	}
	if s[0] == "h2" {
		return 2
	}
	return 1
}

// func getV2RayXHTTPBaseOptions(extraConfig map[string]any) option.V2RayXHTTPBaseOptions {
// 	opts := option.V2RayXHTTPBaseOptions{}
// 	if headers, ok := extraConfig["headers"]; ok {
// 		if headersMap, ok := headers.(map[string]string); ok {
// 			opts.Headers = headersMap
// 		}
// 	}

// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
// 			opts.NoGRPCHeader = noGRPCHeaderb
// 		}
// 	}
// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
// 			opts.NoGRPCHeader = noSSEHeaderb
// 		}
// 	}

//		if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
//			if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
//				opts.ScMaxBufferedPosts = int64(scMaxBufferedPosti)
//			}
//		}
//	}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	// fragment := getFragmentOptions(decoded)
	return T.DialerOptions{
		// TCPFastOpen: !fragment.Enabled,
		// TLSFragment: fragment,
	}
}

func decodeBase64IfNeeded(b64string string) (string, error) {

	decodedBytes, err := decodeBase64FaultTolerant(b64string)

	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toBool(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "1":
		return true
	case "yes":
		return true
	case "on":
		return true
	case "false":
		return false
	case "0":
		return false
	case "no":
		return false
	case "off":
		return false
	default:
		return def
	}
}
func toIntN(s string) *int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &i
}

func toFloatN(s string) *float64 {
	i, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &i
}
func toUInt16(s string, defaultPort uint16) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return uint16(val)
}

func toInt16(s string, defaultPort int16) int16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return int16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func getOneOf(dic map[string]string, headers ...string) (string, error) {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func getOneOfN(dic map[string]string, defaultval string, headers ...string) string {
	for _, h := range headers {
		if str, ok := dic[normalizeStr(h)]; ok {
			return str
		}
	}
	return defaultval
}
