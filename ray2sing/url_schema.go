package ray2sing

import (
	"net/url"
	"regexp"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// HysteriaURLData holds the parsed data from a Hysteria URL.
type UrlSchema struct {
	Scheme   string
	Username string
	Password string
	Hostname string
	Port     uint16
	Name     string
	Params   map[string]string
}

func (u UrlSchema) GetServerOption() T.ServerOptions {
	return T.ServerOptions{
		Server:     u.Hostname,
		ServerPort: u.Port,
	}
}

// func (u UrlSchema) GetRelayOptions() (*T.TurnRelayOptions, error) {
// 	return ParseTurnURL(u.Params["relay"])
// }

// parseHysteria2 parses a given URL and returns a HysteriaURLData struct.
func ParseUrl(inputURL string, defaultPort uint16) (*UrlSchema, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}
	port := toUInt16(parsedURL.Port(), defaultPort)

	data := &UrlSchema{
		Scheme:   parsedURL.Scheme,
		Username: parsedURL.User.Username(),
		Password: getPassword(parsedURL),
		Hostname: parsedURL.Hostname(),
		Port:     port,
		Name:     parsedURL.Fragment,
		Params:   make(map[string]string),
	}
	if isBase64CharsOnly(data.Username) {
		userInfo, err := decodeBase64IfNeeded(data.Username)

		// fmt.Print(userInfo)
		if err == nil && isValidChar(userInfo) {
			// If decoding is successful, use the decoded string
			userDetails := strings.Split(userInfo, ":")
			if len(userDetails) == 2 {
				data.Username = userDetails[0]
				data.Password = userDetails[1]
			}
		}
	}

	data.Params = parseParams(parsedURL.RawQuery)

	return data, nil
}

// parseParams decodes a raw query string while preserving literal "+" characters.
//
// url.URL.Query() (and url.ParseQuery) follow the HTML form convention and turn
// every "+" into a space. Share links do not: v2rayN/v2rayNG emit the ECH
// parameter as `ech=<ech-domain>+https://<doh-url>`, and that "+" is a real
// separator, not an encoded space. Going through Query() silently rewrites it to
// `ech=<ech-domain> https://<doh-url>`, which makes the DoH lookup never fire and
// ends up as a corrupt ECH config.
//
// url.PathUnescape is used instead: it decodes %XX sequences but leaves "+" alone.
func parseParams(rawQuery string) map[string]string {
	params := make(map[string]string)
	if rawQuery == "" {
		return params
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, err := url.PathUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		value, err := url.PathUnescape(rawValue)
		if err != nil {
			value = rawValue
		}
		key = normalizeStr(key)
		if existing, found := params[key]; found && existing != "" {
			params[key] = existing + "," + value
			continue
		}
		params[key] = value
	}
	return params
}

func normalizeStr(ss string) string {
	s := strings.ToLower(strings.TrimSpace(ss))
	for _, r := range []string{"_", "-"} {
		s = strings.ReplaceAll(s, r, " ")

	}
	return s
}

func getPassword(u *url.URL) string {
	if password, ok := u.User.Password(); ok {
		return password
	}
	return ""
}

var base64CharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func isBase64CharsOnly(s string) bool {
	return base64CharRegex.MatchString(s)
}

var validCharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_)(: !~@#$%^&*-]+$`)

func isValidChar(s string) bool {

	return validCharRegex.MatchString(s)
}
