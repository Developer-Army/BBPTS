package services

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

type MobileDynamicTool struct{}

func (t *MobileDynamicTool) Name() string { return "mobile_dynamic" }

func (t *MobileDynamicTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	frida := checkCommand("frida")
	objection := checkCommand("objection")

	if !frida && !objection {
		slog.Debug("mobile_dynamic: frida/objection not found, passive mode")
		return t.passiveScan(targets), nil
	}

	maxThreads := threads
	if LowResourceFromCtx(ctx) {
		if maxThreads > 1 {
			maxThreads = 1
		}
	} else if maxThreads > 2 {
		maxThreads = 2
	}

	events := []Event{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxThreads)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			evts := t.analyzeTarget(ctx, tgt, frida, objection)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *MobileDynamicTool) analyzeTarget(ctx context.Context, target string, frida, objection bool) []Event {
	events := []Event{}

	events = append(events, NewEvent(target, t.Name(), "discovery", map[string]string{
		"scan_type":  "mobile_dynamic",
		"platform":   detectMobilePlatform(target),
		"identifier": target,
	}))

	if frida {
		events = append(events, t.runFrida(ctx, target)...)
	}

	if objection {
		events = append(events, t.runObjection(ctx, target)...)
	}

	events = append(events, t.passiveHints(target)...)

	return events
}

func (t *MobileDynamicTool) runFrida(ctx context.Context, target string) []Event {
	events := []Event{}

	scripts := []struct {
		Name   string
		Script string
	}{
		{"ssl_bypass", `Java.perform(function(){try{var X509TrustManager=Java.use('javax.net.ssl.X509TrustManager');var SSLContext=Java.use('javax.net.ssl.SSLContext');var TrustManager=Java.registerClass({name:'org.threatss.TrustManager',implements:[X509TrustManager],methods:{checkClientTrusted:function(){},checkServerTrusted:function(){},getAcceptedIssuers:function(){return[]}}});var TrustManagers=[TrustManager.$new()];var ctx=SSLContext.getInstance('TLS');ctx.init(null,TrustManagers,null);send({type:'ssl',status:'bypassed'})}catch(e){send({type:'ssl',status:'failed',error:e.toString()})}})`},
		{"network", `Java.perform(function(){var URL=Java.use('java.net.URL');URL.openConnection.overload().implementation=function(){var url=this.toString();send({type:'url',value:url});return this.openConnection()};})`},
		{"prefs", `Java.perform(function(){try{var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();var prefs=ctx.getSharedPreferences('config',0);var map=prefs.getAll();var keys=map.keySet().iterator();while(keys.hasNext()){var k=keys.next();send({type:'pref',key:k,value:String(map.get(k))})}}catch(e){send({type:'pref',error:e.toString()})}})`},
	}

	for _, s := range scripts {
		tmpFile, err := os.CreateTemp("", "frida-*.js")
		if err != nil {
			continue
		}
		tmpFile.WriteString(s.Script)
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		args := []string{"-U", "-f", target, "-l", tmpFile.Name(), "--no-pause"}
		cmd := exec.CommandContext(ctx, "frida", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Debug("mobile_dynamic: frida failed", "script", s.Name, "error", err)
			continue
		}

		events = append(events, t.parseFridaOutput(string(output), target, s.Name)...)
	}

	return events
}

func (t *MobileDynamicTool) parseFridaOutput(output, target, scriptName string) []Event {
	events := []Event{}

	jsonRegex := regexp.MustCompile(`\{[^}]+\}`)
	urlRegex := regexp.MustCompile(`https?://[^\s"']+`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if urls := urlRegex.FindAllString(line, -1); len(urls) > 0 {
			for _, u := range urls {
				events = append(events, NewEvent(u, t.Name(), "api_endpoint", map[string]string{
					"source":    "frida_" + scriptName,
					"scan_type": "mobile_dynamic",
				}))
			}
		}

		if strings.Contains(line, "key") || strings.Contains(line, "token") || strings.Contains(line, "secret") {
			events = append(events, NewEvent(target, t.Name(), "secret_exposed", map[string]string{
				"source":    "frida_" + scriptName,
				"severity":  "medium",
				"scan_type": "mobile_dynamic",
				"data":      truncateDynStr(line, 200),
			}))
		}
	}

	_ = jsonRegex
	return events
}

func (t *MobileDynamicTool) runObjection(ctx context.Context, target string) []Event {
	events := []Event{}

	commands := []struct {
		Name string
		Cmd  string
	}{
		{"ssl", "ios sslpinning disable; android sslpinning disable"},
		{"root", "ios jailbreak disable; android root disable"},
		{"keychain", "ios keychain dump"},
		{"activities", "android hooking list activities"},
		{"services", "android hooking list services"},
		{"clipboard", "ios clipboard dump; android clipboard dump"},
	}

	for _, c := range commands {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		cmd := exec.CommandContext(ctx, "objection", "-g", target, "explore", "-c", c.Cmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		out := strings.TrimSpace(string(output))
		if out == "" {
			continue
		}

		events = append(events, NewEvent(target, t.Name(), "discovery", map[string]string{
			"objection_cmd": c.Name,
			"source":        "objection",
			"scan_type":     "mobile_dynamic",
			"output":        truncateDynStr(out, 300),
		}))

		if c.Name == "keychain" || c.Name == "clipboard" {
			if strings.Contains(out, "key") || strings.Contains(out, "token") {
				events = append(events, NewEvent(target, t.Name(), "secret_exposed", map[string]string{
					"source":    "objection_" + c.Name,
					"severity":  "high",
					"scan_type": "mobile_dynamic",
				}))
			}
		}
	}

	return events
}

func (t *MobileDynamicTool) passiveScan(targets []string) []Event {
	events := []Event{}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		events = append(events, NewEvent(target, t.Name(), "discovery", map[string]string{
			"scan_type": "mobile_dynamic_passive",
			"platform":  detectMobilePlatform(target),
			"note":      "frida/objection not available",
		}))
	}
	return events
}

func (t *MobileDynamicTool) passiveHints(target string) []Event {
	events := []Event{}

	endpoints := []string{"/api/v1/", "/graphql", "/auth", "/login", "/token", "/me", "/config", "/health"}
	for _, ep := range endpoints {
		events = append(events, NewEvent(ep, t.Name(), "api_endpoint", map[string]string{
			"scan_type": "mobile_dynamic_hint",
			"target":    target,
		}))
	}

	return events
}

func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func truncateDynStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
