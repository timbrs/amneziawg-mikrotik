package main

import (
	"encoding/base64"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/timbrs/amneziawg-mikrotik/internal/awg"
)

var version = "dev"

func main() {
	cfg, listenAddr, remoteAddr, err := parseEnv()
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "FATAL: "+err.Error()+"\n")
		os.Exit(1)
	}

	// Определяем версию протокола AmneziaWG по параметрам конфига.
	// v2: если S3 или S4 ненулевые, или хотя бы один H задан диапазоном (Min != Max).
	// v1.5: если нет признаков v2, но задан хотя бы один CPS-шаблон (I1-I5).
	// v1: всё остальное — фиксированные H, без CPS, без S3/S4.
	mode := "v1"
	if cfg.S3 > 0 || cfg.S4 > 0 ||
		cfg.H1.Min != cfg.H1.Max || cfg.H2.Min != cfg.H2.Max ||
		cfg.H3.Min != cfg.H3.Max || cfg.H4.Min != cfg.H4.Max {
		mode = "v2"
	} else if cfg.CPS[0] != nil || cfg.CPS[1] != nil || cfg.CPS[2] != nil ||
		cfg.CPS[3] != nil || cfg.CPS[4] != nil {
		mode = "v1.5"
	}

	if v := os.Getenv("AWG_SOCKET_BUF"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			awg.SocketBufSize = n
		}
	}

	maxProcs := 2
	if v := os.Getenv("AWG_GOMAXPROCS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxProcs = n
		}
	}
	runtime.GOMAXPROCS(maxProcs)

	awg.LogInfo(cfg, "awg-proxy ", version, " ", runtime.GOOS, "/", runtime.GOARCH, " mode=", mode)
	awg.LogInfo(cfg, "listen=", listenAddr.String(), " remote=", remoteAddr.String())
	awg.LogInfo(cfg, "GOMAXPROCS=", strconv.Itoa(maxProcs))
	awg.LogInfo(cfg, "config: S1=", strconv.Itoa(cfg.S1), " S2=", strconv.Itoa(cfg.S2),
		" S3=", strconv.Itoa(cfg.S3), " S4=", strconv.Itoa(cfg.S4))
	awg.LogInfo(cfg, "config: H1=", os.Getenv("AWG_H1"), " H2=", os.Getenv("AWG_H2"),
		" H3=", os.Getenv("AWG_H3"), " H4=", os.Getenv("AWG_H4"))
	awg.LogInfo(cfg, "config: initTotal=", strconv.Itoa(cfg.S1+148),
		" respTotal=", strconv.Itoa(cfg.S2+92), " cookieTotal=", strconv.Itoa(cfg.S3+64))

	proxy := awg.NewProxy(cfg, listenAddr, remoteAddr)

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		awg.LogInfo(cfg, "shutting down")
		close(stop)
	}()

	if err := proxy.Run(stop); err != nil {
		_, _ = io.WriteString(os.Stderr, "FATAL: "+err.Error()+"\n")
		os.Exit(1)
	}
}

func parseEnv() (*awg.Config, *net.UDPAddr, *net.UDPAddr, error) {
	var errs []string

	const el = "list=awg-proxy-env"
	// Collect all required env vars, reporting all missing ones at once
	listen := getRequired("AWG_LISTEN", el, "listen address", ":51820", &errs)
	remote := getRequired("AWG_REMOTE", el, "server endpoint (Endpoint from .conf [Peer])", "1.2.3.4:443", &errs)

	jcStr := getRequired("AWG_JC", el, "junk packet count (Jc from .conf)", "5", &errs)
	jminStr := getRequired("AWG_JMIN", el, "min junk size (Jmin from .conf)", "30", &errs)
	jmaxStr := getRequired("AWG_JMAX", el, "max junk size (Jmax from .conf)", "500", &errs)
	s1Str := getRequired("AWG_S1", el, "init padding bytes (S1 from .conf)", "20", &errs)
	s2Str := getRequired("AWG_S2", el, "response padding bytes (S2 from .conf)", "20", &errs)
	h1Str := getRequired("AWG_H1", el, "init type (H1 from .conf)", "1234567890", &errs)
	h2Str := getRequired("AWG_H2", el, "response type (H2 from .conf)", "1234567891", &errs)
	h3Str := getRequired("AWG_H3", el, "cookie type (H3 from .conf)", "1234567892", &errs)
	h4Str := getRequired("AWG_H4", el, "transport type (H4 from .conf)", "1234567893", &errs)
	serverPubB64 := getRequired("AWG_SERVER_PUB", el, "server public key, base64 (PublicKey from .conf [Peer])", "AAAA...==", &errs)
	clientPubB64 := getRequired("AWG_CLIENT_PUB", el, "client public key, base64 (derive via wg pubkey)", "BBBB...==", &errs)

	// Fail early if any required vars are missing
	if len(errs) > 0 {
		return nil, nil, nil, &envError{msg: buildErrorMsg(errs)}
	}

	// Parse and validate all values, collecting all errors
	var listenAddr, remoteAddr *net.UDPAddr

	if la, err := net.ResolveUDPAddr("udp", listen); err != nil {
		errs = append(errs, "AWG_LISTEN: "+err.Error())
	} else {
		listenAddr = la
	}

	if ra, err := net.ResolveUDPAddr("udp", remote); err != nil {
		errs = append(errs, "AWG_REMOTE: "+err.Error())
	} else {
		remoteAddr = ra
	}

	cfg := &awg.Config{}

	cfg.Jc = collectInt("AWG_JC", jcStr, &errs)
	cfg.Jmin = collectInt("AWG_JMIN", jminStr, &errs)
	cfg.Jmax = collectInt("AWG_JMAX", jmaxStr, &errs)
	cfg.S1 = collectInt("AWG_S1", s1Str, &errs)
	cfg.S2 = collectInt("AWG_S2", s2Str, &errs)
	cfg.H1 = collectHRange("AWG_H1", h1Str, &errs)
	cfg.H2 = collectHRange("AWG_H2", h2Str, &errs)
	cfg.H3 = collectHRange("AWG_H3", h3Str, &errs)
	cfg.H4 = collectHRange("AWG_H4", h4Str, &errs)

	if b, err := base64.StdEncoding.DecodeString(serverPubB64); err != nil {
		errs = append(errs, "AWG_SERVER_PUB: invalid base64: "+err.Error())
	} else if len(b) != 32 {
		errs = append(errs, "AWG_SERVER_PUB: must be 32 bytes, got "+strconv.Itoa(len(b)))
	} else {
		copy(cfg.ServerPub[:], b)
	}

	if b, err := base64.StdEncoding.DecodeString(clientPubB64); err != nil {
		errs = append(errs, "AWG_CLIENT_PUB: invalid base64: "+err.Error())
	} else if len(b) != 32 {
		errs = append(errs, "AWG_CLIENT_PUB: must be 32 bytes, got "+strconv.Itoa(len(b)))
	} else {
		copy(cfg.ClientPub[:], b)
	}

	// Optional v2 parameters.
	if v := os.Getenv("AWG_S3"); v != "" {
		cfg.S3 = collectInt("AWG_S3", v, &errs)
	}
	if v := os.Getenv("AWG_S4"); v != "" {
		cfg.S4 = collectInt("AWG_S4", v, &errs)
	}
	for idx, name := range [5]string{"AWG_I1", "AWG_I2", "AWG_I3", "AWG_I4", "AWG_I5"} {
		if v := os.Getenv(name); v != "" {
			tmpl, err := awg.ParseCPSTemplate(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
			} else {
				cfg.CPS[idx] = tmpl
			}
		}
	}

	if len(errs) > 0 {
		return nil, nil, nil, &envError{msg: buildErrorMsg(errs)}
	}

	cfg.ComputeMAC1Keys()
	cfg.ComputeFastPath()

	cfg.Timeout = 180
	if v := os.Getenv("AWG_TIMEOUT"); v != "" {
		t, err := strconv.Atoi(v)
		if err != nil {
			return nil, nil, nil, &envError{msg: "AWG_TIMEOUT: " + err.Error()}
		}
		cfg.Timeout = t
	}

	cfg.LogLevel = awg.LevelInfo
	switch os.Getenv("AWG_LOG_LEVEL") {
	case "none":
		cfg.LogLevel = awg.LevelNone
	case "error":
		cfg.LogLevel = awg.LevelError
	case "info", "":
		cfg.LogLevel = awg.LevelInfo
	case "debug":
		cfg.LogLevel = awg.LevelDebug
	}

	return cfg, listenAddr, remoteAddr, nil
}

func getRequired(name, envList, hint, example string, errs *[]string) string {
	v := os.Getenv(name)
	if v == "" {
		*errs = append(*errs, name+" is not set -- "+hint+
			"\n    /container/envs/add "+envList+" key="+name+" value=\""+example+"\"")
	}
	return v
}

func collectInt(name, s string, errs *[]string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		*errs = append(*errs, name+": expected integer: "+err.Error())
	}
	return n
}

func collectUint32(name, s string, errs *[]string) uint32 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		*errs = append(*errs, name+": expected uint32: "+err.Error())
	}
	return uint32(n)
}

func collectHRange(name, s string, errs *[]string) awg.HRange {
	before, after, found := strings.Cut(s, "-")
	lo := collectUint32(name, before, errs)
	if !found {
		return awg.HRange{Min: lo, Max: lo}
	}
	hi := collectUint32(name+" max", after, errs)
	if lo > hi {
		*errs = append(*errs, name+": min > max")
	}
	return awg.HRange{Min: lo, Max: hi}
}

func buildErrorMsg(errs []string) string {
	msg := "configuration errors:\n"
	for _, e := range errs {
		msg += "  - " + e + "\n"
	}
	msg += "\nAll AWG_* parameters can be found in your AmneziaWG .conf file.\n"
	msg += "Use the configurator at docs/configurator.html to generate MikroTik commands.\n"
	msg += "See README.md for the full configuration reference."
	return msg
}

type envError struct {
	msg string
}

func (e *envError) Error() string { return e.msg }
