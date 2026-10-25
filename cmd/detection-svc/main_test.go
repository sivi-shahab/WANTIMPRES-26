package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wantimpres26/internal/detect"
)

func TestScanText(t *testing.T) {
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		scanText(nil, nil, nil)(w, httptest.NewRequest(http.MethodPost, "/scan/text", strings.NewReader(body)))
		return w
	}
	w := post(`{"content": "NIK 3201011505900001", "channel": "ai_gateway", "direction": "request"}`)
	var res detect.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); w.Code != 200 || err != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if res.Sensitivity != "confidential" || len(res.Classes) != 1 || res.Classes[0].Type != "PII_ID.NIK" || strings.Contains(w.Body.String(), "3201011505900001") {
		t.Errorf("response %s", w.Body.String())
	}
	if w := post(`{"content": "` + strings.Repeat("a", maxContent+1) + `"}`); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d", w.Code)
	}
	if w := post(`{`); w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", w.Code)
	}
}
