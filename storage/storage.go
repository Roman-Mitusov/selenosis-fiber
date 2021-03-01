package storage

import (
	"github.com/Roman-Mitusov/selenosis-fiber/browser"
	"github.com/Roman-Mitusov/selenosis-fiber/tools"
	"sync"
)

//Storage ...
type Storage struct {
	sessions map[string]*browser.RunningBrowserPod
	sync.RWMutex
}

//New ...
func New() *Storage {
	return &Storage{
		sessions: make(map[string]*browser.RunningBrowserPod),
	}
}

//Put ...
func (s *Storage) Put(sessionID string, service *browser.RunningBrowserPod) {
	s.Lock()
	defer s.Unlock()
	s.sessions[sessionID] = service
}

//Delete ...
func (s *Storage) Delete(sessionID string) {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, sessionID)
}

//List ...
func (s *Storage) List() []browser.RunningBrowserPod {
	s.Lock()
	defer s.Unlock()
	var l []browser.RunningBrowserPod

	for _, p := range s.sessions {
		c := *p
		c.Uptime = tools.TimeElapsed(c.Started)
		l = append(l, c)
	}
	return l

}

//Len ...
func (s *Storage) Len() int {
	s.Lock()
	defer s.Unlock()

	return len(s.sessions)
}
