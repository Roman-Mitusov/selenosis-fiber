package browser

import (
	"context"
	"github.com/Roman-Mitusov/selenosis-fiber/selenium"
	"io"
	"net/url"
	"time"

	apiv1 "k8s.io/api/core/v1"
)

//Meta describes standart metadata
//Labels and annotations for browser pod
type Meta struct {
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

//Spec describes  specific kubernetes specs for Browser Pod
type Spec struct {
	Resources    apiv1.ResourceRequirements `yaml:"resources,omitempty" json:"resources,omitempty"`
	HostAliases  []apiv1.HostAlias          `yaml:"hostAliases,omitempty" json:"hostAliases,omitempty"`
	EnvVars      []apiv1.EnvVar             `yaml:"env,omitempty" json:"env,omitempty"`
	NodeSelector map[string]string          `yaml:"nodeSelector,omitempty" json:"nodeSelector,omitempty"`
	Affinity     apiv1.Affinity             `yaml:"affinity,omitempty" json:"affinity,omitempty"`
	DNSConfig    apiv1.PodDNSConfig         `yaml:"dnsConfig,omitempty" json:"dnsConfig,omitempty"`
	Tolerations  []apiv1.Toleration         `yaml:"tolerations,omitempty" json:"tolerations,omitempty"`
}

//Browser specification describes settings for Browser Pod
type SpecForBrowser struct {
	BrowserName    string `yaml:"-" json:"-"`
	BrowserVersion string `yaml:"-" json:"-"`
	Image          string `yaml:"image" json:"image"`
	Path           string `yaml:"path" json:"path"`
	Privileged     bool   `yaml:"privileged" json:"privileged"`
	Meta           Meta   `yaml:"meta" json:"meta"`
	Spec           Spec   `yaml:"spec" json:"spec"`
}

//FinalBrowserPodSpec describes data required for creating Browser Pod
//Final spec for Browser Pod
type FinalBrowserPodSpec struct {
	SessionID             string
	RequestedCapabilities selenium.Capabilities
	Template              *SpecForBrowser
}

//Running browser Pod specification ...
type RunningBrowserPod struct {
	SessionID  string            `json:"id"`
	URL        *url.URL          `json:"-"`
	Labels     map[string]string `json:"labels"`
	OnTimeout  chan struct{}     `json:"-"`
	CancelFunc func()            `json:"-"`
	Status     ServiceStatus     `json:"-"`
	Started    time.Time         `json:"started"`
	Uptime     string            `json:"uptime"`
}

//Status of Browser Pod ...
type ServiceStatus string

//Event which describes the status of Browser Pod ...
type Event struct {
	Type    EventType
	Service *RunningBrowserPod
}

//EventType for Browser Pod ...
type EventType string

const (
	Added   EventType = "Added"
	Updated EventType = "Updated"
	Deleted EventType = "Deleted"

	Pending ServiceStatus = "Pending"
	Running ServiceStatus = "Running"
	Unknown ServiceStatus = "Unknown"
)

//Browser interface which allows to start, delete, list, watch and see the logs of running Browser Pod ...
type Platform interface {
	Create(*FinalBrowserPodSpec) (*RunningBrowserPod, error)
	Delete(string) error
	List() ([]*RunningBrowserPod, error)
	Watch() <-chan Event
	Logs(context.Context, string) (io.ReadCloser, error)
}
