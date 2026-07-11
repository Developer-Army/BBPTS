package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type BusinessLogicTool struct{}

var businessLogicKeywords = []string{
	"price", "amount", "cost", "total", "payment", "checkout",
	"coupon", "discount", "promo", "voucher", "credit", "balance",
	"quantity", "qty", "count", "tier", "plan", "upgrade",
	"withdraw", "transfer", "redeem",
}

type logicTest struct {
	name        string
	payload     string
	contentType string
	method      string
}

func (t *BusinessLogicTool) Name() string {
	return "business_logic"
}

func (t *BusinessLogicTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 15
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		if !isBusinessLogicEndpoint(target) {
			return nil, nil
		}

		client := NewSafeHTTPClient(10 * time.Second)
		var events []recon.Event

		events = append(events, t.testAmountManipulation(ctx, client, target, scanCtx.Headers)...)

		events = append(events, t.testCouponAbuse(ctx, client, target, scanCtx.Headers)...)

		events = append(events, t.testQuantityOverflow(ctx, client, target, scanCtx.Headers)...)

		return events, nil
	})
}

func (t *BusinessLogicTool) testAmountManipulation(ctx context.Context, client *http.Client, target string, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event

	tests := []logicTest{
		{name: "negative_amount", payload: `{"amount":-1}`, contentType: "application/json", method: "POST"},
		{name: "zero_amount", payload: `{"amount":0}`, contentType: "application/json", method: "POST"},
		{name: "fractional_amount", payload: `{"amount":0.001}`, contentType: "application/json", method: "POST"},
		{name: "overflow_amount", payload: `{"amount":99999999}`, contentType: "application/json", method: "POST"},
		{name: "price_zero", payload: `{"price":0}`, contentType: "application/json", method: "POST"},
		{name: "negative_price", payload: `{"price":-100}`, contentType: "application/json", method: "POST"},
		{name: "currency_confusion", payload: `{"amount":100,"currency":"JPY"}`, contentType: "application/json", method: "POST"},
		{name: "negative_total", payload: `{"total":-50}`, contentType: "application/json", method: "POST"},
		{name: "float_overflow", payload: `{"amount":1.7976931348623157e+308}`, contentType: "application/json", method: "POST"},
	}

	for _, test := range tests {
		status, body := t.doPOST(ctx, client, target, test.payload, test.contentType, baseHeaders)
		if status == 0 {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		successIndicators := []string{"success", "confirmed", "completed", "processed", "created", "approved"}
		for _, indicator := range successIndicators {
			if strings.Contains(bodyStr, indicator) && status == 200 {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Business Logic Flaw - Amount Manipulation",
					"severity":    "high",
					"test":        test.name,
					"payload":     test.payload,
					"status":      fmt.Sprintf("%d", status),
					"description": fmt.Sprintf("Business logic test '%s' returned success on %s", test.name, target),
				}, "high"))
				slog.Warn("Business logic flaw detected", "target", target, "test", test.name)
				break
			}
		}
	}

	return events
}

func (t *BusinessLogicTool) testCouponAbuse(ctx context.Context, client *http.Client, target string, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event

	coupons := []string{
		"SAVE10", "SAVE20", "SAVE50", "SAVE100",
		"ADMIN", "TEST", "FREE", "DISCOUNT",
		"WELCOME10", "WELCOME20", "FIRST50",
		"VIP100", "PREMIUM", "UNLIMITED",
	}

	for _, coupon := range coupons {
		payload := fmt.Sprintf(`{"coupon":%q}`, coupon)
		status, body := t.doPOST(ctx, client, target, payload, "application/json", baseHeaders)
		if status == 0 {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		validIndicators := []string{"applied", "valid", "accepted", "discount", "success"}
		for _, indicator := range validIndicators {
			if strings.Contains(bodyStr, indicator) && status == 200 {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Business Logic Flaw - Coupon Abuse",
					"severity":    "medium",
					"test":        "coupon_enumeration",
					"coupon":      coupon,
					"status":      fmt.Sprintf("%d", status),
					"description": fmt.Sprintf("Coupon '%s' appears to be valid on %s", coupon, target),
				}, "medium"))
				slog.Warn("Coupon abuse potential", "target", target, "coupon", coupon)
				break
			}
		}
	}

	return events
}

func (t *BusinessLogicTool) testQuantityOverflow(ctx context.Context, client *http.Client, target string, baseHeaders map[string]string) []recon.Event {
	var events []recon.Event

	tests := []logicTest{
		{name: "negative_quantity", payload: `{"quantity":-1}`, contentType: "application/json", method: "POST"},
		{name: "zero_quantity", payload: `{"quantity":0}`, contentType: "application/json", method: "POST"},
		{name: "fractional_quantity", payload: `{"quantity":1.5}`, contentType: "application/json", method: "POST"},
		{name: "overflow_quantity", payload: `{"quantity":9999999}`, contentType: "application/json", method: "POST"},
		{name: "string_quantity", payload: `{"quantity":"1 OR 1=1"}`, contentType: "application/json", method: "POST"},
		{name: "null_quantity", payload: `{"quantity":null}`, contentType: "application/json", method: "POST"},
		{name: "array_quantity", payload: `{"quantity":[1,2,3]}`, contentType: "application/json", method: "POST"},
	}

	for _, test := range tests {
		status, body := t.doPOST(ctx, client, target, test.payload, test.contentType, baseHeaders)
		if status == 0 {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		successIndicators := []string{"success", "confirmed", "completed", "processed", "created"}
		for _, indicator := range successIndicators {
			if strings.Contains(bodyStr, indicator) && status == 200 {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Business Logic Flaw - Quantity Manipulation",
					"severity":    "high",
					"test":        test.name,
					"payload":     test.payload,
					"status":      fmt.Sprintf("%d", status),
					"description": fmt.Sprintf("Business logic test '%s' returned success on %s", test.name, target),
				}, "high"))
				slog.Warn("Business logic flaw detected", "target", target, "test", test.name)
				break
			}
		}
	}

	return events
}

func (t *BusinessLogicTool) doPOST(ctx context.Context, client *http.Client, target, payload, contentType string, baseHeaders map[string]string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(payload))
	if err != nil {
		return 0, nil
	}
	for k, v := range baseHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 64*1024)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil || len(body) > 64*1024 {
			break
		}
	}
	return resp.StatusCode, body
}

func isBusinessLogicEndpoint(target string) bool {
	lower := strings.ToLower(target)
	for _, kw := range businessLogicKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

var _ recon.Tool = (*BusinessLogicTool)(nil)
