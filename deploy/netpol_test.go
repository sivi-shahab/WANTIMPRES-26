// Package deploy holds the Kubernetes manifests; this test checks them.
package deploy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// A minimal model of the manifests: enough of NetworkPolicy semantics to evaluate a flow, and of pod templates to
// know each workload's labels, service account and mTLS allow list.

type selector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

func (s *selector) matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	return true
}

type peer struct {
	PodSelector       *selector `json:"podSelector"`
	NamespaceSelector *selector `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR string `json:"cidr"`
	} `json:"ipBlock"`
}

type rule struct {
	From  []peer `json:"from"`
	To    []peer `json:"to"`
	Ports []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type netpol struct {
	Metadata struct{ Name string } `json:"metadata"`
	Spec     struct {
		PodSelector selector `json:"podSelector"`
		PolicyTypes []string `json:"policyTypes"`
		Ingress     []rule   `json:"ingress"`
		Egress      []rule   `json:"egress"`
	} `json:"spec"`
}

// endpoint is a pod (namespace + labels) or an address outside the cluster.
type endpoint struct {
	name   string
	ns     string
	labels map[string]string
	ip     string
}

func pod(ns string, labels map[string]string) endpoint {
	return endpoint{name: ns + "/" + labels["app"] + labels["k8s-app"], ns: ns, labels: labels}
}

func (p peer) matches(e endpoint) bool {
	if p.IPBlock != nil {
		// Pod addresses under an ipBlock are implementation-defined; only external addresses count here.
		pfx, err := netip.ParsePrefix(p.IPBlock.CIDR)
		return err == nil && e.ip != "" && pfx.Contains(netip.MustParseAddr(e.ip))
	}
	if e.ip != "" {
		return false
	}
	nsOK := e.ns == "wantimpres26"
	if p.NamespaceSelector != nil {
		nsOK = p.NamespaceSelector.matches(map[string]string{"kubernetes.io/metadata.name": e.ns})
	}
	return nsOK && (p.PodSelector == nil || p.PodSelector.matches(e.labels))
}

func (r rule) allows(peers []peer, other endpoint, port int, proto string) bool {
	portOK := len(r.Ports) == 0
	for _, p := range r.Ports {
		pr := p.Protocol
		if pr == "" {
			pr = "TCP"
		}
		portOK = portOK || (p.Port == port && pr == proto)
	}
	return portOK && (len(peers) == 0 || slices.ContainsFunc(peers, func(p peer) bool { return p.matches(other) }))
}

type manifests struct {
	policies []netpol
	pods     map[string]workload // by app label
	accounts []string
}

type workload struct {
	labels         map[string]string
	serviceAccount string
	mtlsAllow      []string
	ports          []int
}

func load(t *testing.T) manifests {
	t.Helper()
	m := manifests{pods: map[string]workload{}}
	files, _ := filepath.Glob("base/*.yaml")
	for _, f := range files {
		if filepath.Base(f) == "kustomization.yaml" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(raw), "\n---") {
			var head struct {
				Kind     string
				Metadata struct{ Name string }
			}
			if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			switch head.Kind {
			case "NetworkPolicy":
				var np netpol
				if err := yaml.Unmarshal([]byte(doc), &np); err != nil {
					t.Fatalf("%s %s: %v", f, head.Metadata.Name, err)
				}
				m.policies = append(m.policies, np)
			case "ServiceAccount":
				m.accounts = append(m.accounts, head.Metadata.Name)
			case "Deployment", "CronJob":
				var d struct {
					Spec struct {
						Template    podTemplate `json:"template"`
						JobTemplate struct {
							Spec struct {
								Template podTemplate `json:"template"`
							} `json:"spec"`
						} `json:"jobTemplate"`
					} `json:"spec"`
				}
				if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
					t.Fatalf("%s %s: %v", f, head.Metadata.Name, err)
				}
				tpl := d.Spec.Template
				if head.Kind == "CronJob" {
					tpl = d.Spec.JobTemplate.Spec.Template
				}
				w := workload{labels: tpl.Metadata.Labels, serviceAccount: tpl.Spec.ServiceAccountName}
				for _, c := range tpl.Spec.Containers {
					for _, e := range c.Env {
						if e.Name == "MTLS_ALLOW" {
							w.mtlsAllow = strings.Split(e.Value, ",")
						}
					}
					for _, p := range c.Ports {
						w.ports = append(w.ports, p.ContainerPort)
					}
				}
				m.pods[w.labels["app"]] = w
			}
		}
	}
	return m
}

type podTemplate struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Env []struct {
				Name, Value string
			} `json:"env"`
			Ports []struct {
				ContainerPort int `json:"containerPort"`
			} `json:"ports"`
		} `json:"containers"`
	} `json:"spec"`
}

// allowed: src may send (its egress) and dst may receive (its ingress); only namespace wantimpres26 has policies here.
func (m manifests) allowed(src, dst endpoint, port int, proto string) bool {
	side := func(e endpoint, typ string, pick func(netpol) ([]rule, func(rule) []peer), other endpoint) bool {
		if e.ns != "wantimpres26" {
			return true
		}
		isolated := false
		for _, np := range m.policies {
			if !slices.Contains(np.Spec.PolicyTypes, typ) || !np.Spec.PodSelector.matches(e.labels) {
				continue
			}
			isolated = true
			rules, peers := pick(np)
			for _, r := range rules {
				if r.allows(peers(r), other, port, proto) {
					return true
				}
			}
		}
		return !isolated
	}
	egress := func(np netpol) ([]rule, func(rule) []peer) {
		return np.Spec.Egress, func(r rule) []peer { return r.To }
	}
	ingress := func(np netpol) ([]rule, func(rule) []peer) {
		return np.Spec.Ingress, func(r rule) []peer { return r.From }
	}
	return side(src, "Egress", egress, dst) && side(dst, "Ingress", ingress, src)
}

// Ticket 40 AC: default-deny in namespace wantimpres26, every §5.2 flow still open, the oracle paths (G1) closed.
func TestNetworkPolicy(t *testing.T) {
	m := load(t)
	defaultDeny := slices.ContainsFunc(m.policies, func(np netpol) bool {
		return len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 &&
			slices.Contains(np.Spec.PolicyTypes, "Ingress") && slices.Contains(np.Spec.PolicyTypes, "Egress")
	})
	if !defaultDeny {
		t.Fatal("no default-deny NetworkPolicy (empty podSelector, Ingress+Egress, no rules)")
	}
	p := func(app string) endpoint {
		w, ok := m.pods[app]
		if !ok {
			t.Fatalf("no workload %s", app)
		}
		return pod("wantimpres26", w.labels)
	}
	ext := func(ns, app string) endpoint { return pod(ns, map[string]string{"app": app}) }
	dns := pod("kube-system", map[string]string{"k8s-app": "kube-dns"})
	db := endpoint{name: "postgres 10.20.30.40", ip: "10.20.30.40"}

	type flow struct {
		src, dst endpoint
		port     int
	}
	open := []flow{
		{p("ai-gateway"), p("control-plane"), 8443}, {p("mcp-gateway"), p("control-plane"), 8443}, // BUN --> OPA
		{ext("ingress-nginx", "controller"), p("control-plane"), 8080}, // admin API, SCIM
		{p("mcp-gateway"), p("control-plane"), 8080},                   // tools/list, approvals
		{ext("monitoring", "prometheus"), p("control-plane"), 8080},
		{ext("core-banking", "teller"), p("ai-gateway"), 8080}, {ext("agents", "invoice-bot"), p("mcp-gateway"), 8080}, // apps and agents → PEPs
		{p("ai-gateway"), p("detection-svc"), 8443}, {p("mcp-gateway"), p("detection-svc"), 8443}, // PEP --> DS
		{p("detection-svc"), p("model-inference"), 8443}, // DS --> MI
		{p("ai-gateway"), p("token-vault"), 8080},        // GW --> TV
		{p("connector-worker"), p("tika"), 9998}, {p("control-plane"), p("tika"), 9998},
		{ext("monitoring", "alertmanager"), p("siem-export"), 8080},
		{ext("ingress-nginx", "controller"), p("connector-worker"), 8080},
		{ext("monitoring", "prometheus"), p("ai-gateway"), 8282},
	}
	for app := range m.pods {
		open = append(open, flow{p(app), dns, 53})
	}
	for _, app := range []string{"control-plane", "ai-gateway", "mcp-gateway", "detection-svc", "token-vault", "event-ingest", "siem-export", "connector-worker", "audit-anchor"} {
		open = append(open, flow{p(app), db, 5432})
	}
	for _, f := range open {
		proto := "TCP"
		if f.port == 53 {
			proto = "UDP"
		}
		if !m.allowed(f.src, f.dst, f.port, proto) {
			t.Errorf("flow %s → %s:%d is blocked", f.src.name, f.dst.name, f.port)
		}
	}
	closed := []flow{
		{p("siem-export"), p("detection-svc"), 8443}, {p("event-ingest"), p("model-inference"), 8443}, // oracle (G1)
		{p("ai-gateway"), p("model-inference"), 8443}, {p("connector-worker"), p("detection-svc"), 8443},
		{ext("core-banking", "teller"), p("detection-svc"), 8443}, {ext("core-banking", "teller"), p("model-inference"), 8443},
		{ext("core-banking", "teller"), p("control-plane"), 8443}, {p("connector-worker"), p("control-plane"), 8443}, // bundle
		{p("detection-svc"), p("control-plane"), 8443}, {p("siem-export"), p("token-vault"), 8080},
		{ext("core-banking", "teller"), p("control-plane"), 8080}, {ext("core-banking", "teller"), p("token-vault"), 8080},
		{p("model-inference"), db, 443}, {p("tika"), db, 443}, // no exfiltration from model or parser
		{p("ai-gateway"), p("event-ingest"), 8080},
	}
	for _, f := range closed {
		if m.allowed(f.src, f.dst, f.port, "TCP") {
			t.Errorf("flow %s → %s:%d is open", f.src.name, f.dst.name, f.port)
		}
	}

	// Identity and network agree: every workload has its own service account (its SPIFFE ID), every ID in an
	// MTLS_ALLOW exists, and the network lets it reach that port.
	for app, w := range m.pods {
		if w.serviceAccount != app || !slices.Contains(m.accounts, app) {
			t.Errorf("%s runs as service account %q (want its own, declared in serviceaccounts.yaml)", app, w.serviceAccount)
		}
		for _, id := range w.mtlsAllow {
			sa, ok := strings.CutPrefix(id, "spiffe://wantimpres26.bank/ns/wantimpres26/sa/")
			if _, exists := m.pods[sa]; !ok || !exists {
				t.Errorf("%s MTLS_ALLOW %q: no such workload", app, id)
				continue
			}
			if !slices.Contains(w.ports, 8443) || !m.allowed(p(sa), p(app), 8443, "TCP") {
				t.Errorf("%s allows %s by mTLS but the network does not", app, sa)
			}
		}
	}
	if fmt.Sprint(m.pods["model-inference"].mtlsAllow) != "[spiffe://wantimpres26.bank/ns/wantimpres26/sa/detection-svc]" {
		t.Errorf("model-inference MTLS_ALLOW %v", m.pods["model-inference"].mtlsAllow)
	}
}
