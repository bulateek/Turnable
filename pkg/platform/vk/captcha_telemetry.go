package vk

// The PoW envelope structure and telemetry probe schema below are ported from
// samosvalishe/free-turn-proxy (internal/provider/vk/internal/captcha/pow.go),
// which reverse-engineered VK's captcha widget after it started requiring a
// simulated browser fingerprint alongside the PoW hash. Used under the project's
// Happy Bunny License (MIT-style).
// https://github.com/samosvalishe/free-turn-proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// captchaPowResult mirrors window.captchaPowResult: the widget doesn't send a bare
// hash, it sends this envelope, field order matching JSON.stringify on the page.
type captchaPowResult struct {
	Hash       string          `json:"hash"`
	Nonce      int             `json:"nonce"`
	DurationMs int64           `json:"duration_ms"`
	Telemetry  json.RawMessage `json:"telemetry"`
	TelHash    string          `json:"tel_hash"`
}

// buildPowEnvelope assembles the base64 PoW envelope sent as the "hash" field of
// captcha requests: the solved hash/nonce plus a simulated browser fingerprint and
// its canonicalized hash, prefixed with the page's own envelope prefix (e.g. "v2.").
func (V *Handler) buildPowEnvelope(prefix, hash string, nonce int) (string, error) {
	telemetry, err := marshalCaptchaJS(V.captchaTelemetry())
	if err != nil {
		return "", err
	}

	telHash, err := captchaTelemetryHash(telemetry)
	if err != nil {
		return "", err
	}

	envelope, err := marshalCaptchaJS(captchaPowResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: captchaPowDurationMs(nonce),
		Telemetry:  telemetry,
		TelHash:    telHash,
	})
	if err != nil {
		return "", err
	}

	return prefix + base64.StdEncoding.EncodeToString(envelope), nil
}

// captchaTelemetryHash re-encodes telemetry with alphabetically sorted keys (which
// json.Marshal does automatically for a map) before hashing, mirroring the page's
// own canonicalizer.
func captchaTelemetryHash(telemetry []byte) (string, error) {
	var v any
	if err := json.Unmarshal(telemetry, &v); err != nil {
		return "", err
	}
	canonical, err := marshalCaptchaJS(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// marshalCaptchaJS encodes without HTML-escaping, matching JSON.stringify which
// doesn't touch < > &.
func marshalCaptchaJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// captchaPowDurationMs approximates the synchronous solve loop's wall-clock time:
// the real widget's inner loop runs at roughly 0.015ms per nonce tried.
func captchaPowDurationMs(nonce int) int64 {
	d := int64(math.Round(float64(nonce+1) * 0.015))
	if d < 1 {
		d = 1
	}
	return d
}

// captchaProbe wraps a successfully-collected telemetry probe result.
type captchaProbe struct {
	OK     bool `json:"ok"`
	Result any  `json:"result"`
}

func probeOK(result any) captchaProbe { return captchaProbe{OK: true, Result: result} }

// captchaTelemetryData is the "telemetry" object of the PoW envelope: a battery of
// browser-fingerprinting probes the real widget runs before solving PoW.
type captchaTelemetryData struct {
	Globals          captchaProbe `json:"globals"`
	UA               captchaProbe `json:"ua"`
	Frame            captchaProbe `json:"frame"`
	MatchMedia       captchaProbe `json:"match_media"`
	Plugins          captchaProbe `json:"plugins"`
	NavTamper        captchaProbe `json:"nav_tamper"`
	Referrer         captchaProbe `json:"referrer"`
	DevTools         captchaProbe `json:"devtools"`
	CSS              captchaProbe `json:"css"`
	NativeIntegrity  captchaProbe `json:"native_integrity"`
	CookieTest       captchaProbe `json:"cookie_test"`
	AncestorOrigins  captchaProbe `json:"ancestor_origins"`
	SandboxBehavior  captchaProbe `json:"sandbox_behavior"`
	MaxTouchPoints   captchaProbe `json:"max_touch_points"`
	TimezoneLocale   captchaProbe `json:"timezone_locale"`
	DevicePixelRatio captchaProbe `json:"device_pixel_ratio"`
}

type captchaGlobalsProbe struct {
	Doc          bool `json:"doc"`
	Win          bool `json:"win"`
	Nav          bool `json:"nav"`
	Webdriver    bool `json:"webdriver"`
	Subtle       bool `json:"subtle"`
	Secure       bool `json:"secure"`
	GCS          bool `json:"gcs"`
	RAF          bool `json:"raf"`
	Wasm         bool `json:"wasm"`
	PluginsLen   int  `json:"plugins_len"`
	LanguagesLen int  `json:"languages_len"`
	HW           int  `json:"hw"`
	Mem          *int `json:"mem"`
}

type captchaBrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type captchaUADataProbe struct {
	Brands       []captchaBrand `json:"brands"`
	Platform     string         `json:"platform"`
	Mobile       bool           `json:"mobile"`
	Architecture *string        `json:"architecture"`
}

type captchaUAProbe struct {
	UserAgent     string              `json:"userAgent"`
	UserAgentData *captchaUADataProbe `json:"userAgentData"`
}

type captchaFrameProbe struct {
	FrameElement       *string `json:"frameElement"`
	AncestorOriginsLen int     `json:"ancestorOriginsLen"`
	ParentAccessible   bool    `json:"parentAccessible"`
}

type captchaMatchMediaProbe struct {
	PrefersDark   bool `json:"prefersDark"`
	PrefersLight  bool `json:"prefersLight"`
	ReducedMotion bool `json:"reducedMotion"`
	PointerFine   bool `json:"pointerFine"`
}

type captchaPluginsProbe struct {
	Length       int        `json:"length"`
	Names        []string   `json:"names"`
	Descriptions []string   `json:"descriptions"`
	MimeTypes    [][]string `json:"mimeTypes"`
	IsChrome     bool       `json:"isChrome"`
}

type captchaNavTamperProbe struct {
	Tampered       bool   `json:"tampered"`
	ElCtor         string `json:"el_ctor"`
	StyleCtor      string `json:"style_ctor"`
	NavCtor        string `json:"nav_ctor"`
	AlertNative    bool   `json:"alert_native"`
	ToStringNative bool   `json:"to_string_native"`
}

type captchaReferrerProbe struct {
	Referrer string `json:"referrer"`
	InIframe bool   `json:"inIframe"`
	Domain   string `json:"domain"`
}

type captchaDevToolsProbe struct {
	Open    bool `json:"open"`
	DelayMs int  `json:"delay_ms"`
}

type captchaCSSProbe struct {
	ExpectedMissing int `json:"expectedMissing"`
}

type captchaNativeIntegrityProbe struct {
	ProtoMatch             bool `json:"protoMatch"`
	XHRNative              bool `json:"xhrNative"`
	XHRSendNative          bool `json:"xhrSendNative"`
	AddEventListenerNative bool `json:"addEventListenerNative"`
	AlertNative            bool `json:"alertNative"`
	ToStringNative         bool `json:"toStringNative"`
}

type captchaCookieTestProbe struct {
	Write bool `json:"write"`
}

type captchaAncestorOriginsProbe struct {
	AncestorOrigin *string `json:"ancestorOrigin"`
}

type captchaSandboxBehaviorProbe struct {
	OriginIsNull   bool `json:"originIsNull"`
	LocalStorage   bool `json:"localStorage"`
	SessionStorage bool `json:"sessionStorage"`
}

type captchaMaxTouchPointsProbe struct {
	MaxTouchPoints int `json:"maxTouchPoints"`
}

type captchaTimezoneLocaleProbe struct {
	Timezone  string   `json:"timezone"`
	Languages []string `json:"languages"`
}

type captchaDevicePixelRatioProbe struct {
	DPR              float64 `json:"dpr"`
	Orientation      string  `json:"orientation"`
	OrientationAngle int     `json:"orientationAngle"`
}

var chromePDFPluginNames = []string{
	"PDF Viewer",
	"Chrome PDF Viewer",
	"Chromium PDF Viewer",
	"Microsoft Edge PDF Viewer",
	"WebKit built-in PDF",
}

const chromePDFDescription = "Portable Document Format"

var chromePDFMimeTypes = []string{"application/pdf", "text/pdf"}

func chromePlugins() captchaPluginsProbe {
	out := captchaPluginsProbe{
		Length:       len(chromePDFPluginNames),
		Names:        chromePDFPluginNames,
		Descriptions: make([]string, len(chromePDFPluginNames)),
		MimeTypes:    make([][]string, len(chromePDFPluginNames)),
		IsChrome:     true,
	}
	for i := range chromePDFPluginNames {
		out.Descriptions[i] = chromePDFDescription
		out.MimeTypes[i] = chromePDFMimeTypes
	}
	return out
}

var reCaptchaBrand = regexp.MustCompile(`"([^"]+)";v="([^"]+)"`)

// parseCaptchaBrands turns a Sec-CH-UA header value into the brands array the
// real navigator.userAgentData.brands would report.
func parseCaptchaBrands(secChUa string) []captchaBrand {
	matches := reCaptchaBrand.FindAllStringSubmatch(secChUa, -1)
	brands := make([]captchaBrand, 0, len(matches))
	for _, m := range matches {
		brands = append(brands, captchaBrand{Brand: m[1], Version: m[2]})
	}
	return brands
}

// captchaTelemetry builds the telemetry probe object for the handler's current
// browser profile. All three pool profiles (Windows/macOS/Linux Chrome desktop)
// share the same device shape as the existing "device" JSON param, so most values
// here just mirror that.
func (V *Handler) captchaTelemetry() captchaTelemetryData {
	p := V.profile
	isMobile := p.SecChUaMobile == "?1"
	platform := strings.Trim(p.SecChUaPlatform, `"`)
	brands := parseCaptchaBrands(p.SecChUa)

	plugins := captchaPluginsProbe{Names: []string{}, Descriptions: []string{}, MimeTypes: [][]string{}}
	if !isMobile {
		plugins = chromePlugins()
	}

	return captchaTelemetryData{
		Globals: probeOK(captchaGlobalsProbe{
			Doc: true, Win: true, Nav: true,
			Webdriver:    false,
			Subtle:       true,
			Secure:       true,
			GCS:          true,
			RAF:          true,
			Wasm:         true,
			PluginsLen:   plugins.Length,
			LanguagesLen: 2,
			HW:           8,
		}),
		UA: probeOK(captchaUAProbe{
			UserAgent: p.UserAgent,
			UserAgentData: &captchaUADataProbe{
				Brands:   brands,
				Platform: platform,
				Mobile:   isMobile,
			},
		}),
		Frame:      probeOK(captchaFrameProbe{ParentAccessible: true}),
		MatchMedia: probeOK(captchaMatchMediaProbe{PrefersLight: true, PointerFine: !isMobile}),
		Plugins:    probeOK(plugins),
		NavTamper: probeOK(captchaNavTamperProbe{
			ElCtor: "HTMLDivElement", StyleCtor: "CSSStyleDeclaration", NavCtor: "Navigator",
			AlertNative: true, ToStringNative: true,
		}),
		Referrer: probeOK(captchaReferrerProbe{
			Referrer: "https://vk.com/",
			Domain:   "vk.com",
		}),
		DevTools: probeOK(captchaDevToolsProbe{}),
		CSS:      probeOK(captchaCSSProbe{}),
		NativeIntegrity: probeOK(captchaNativeIntegrityProbe{
			ProtoMatch: true, XHRNative: true, XHRSendNative: true,
			AddEventListenerNative: true, AlertNative: true, ToStringNative: true,
		}),
		CookieTest:      probeOK(captchaCookieTestProbe{Write: true}),
		AncestorOrigins: probeOK(captchaAncestorOriginsProbe{}),
		SandboxBehavior: probeOK(captchaSandboxBehaviorProbe{LocalStorage: true, SessionStorage: true}),
		MaxTouchPoints:  probeOK(captchaMaxTouchPointsProbe{MaxTouchPoints: 0}),
		TimezoneLocale:  probeOK(captchaTimezoneLocaleProbe{Timezone: "Europe/Moscow", Languages: []string{"en-US", "en"}}),
		DevicePixelRatio: probeOK(captchaDevicePixelRatioProbe{
			DPR:         1,
			Orientation: "landscape-primary",
		}),
	}
}
