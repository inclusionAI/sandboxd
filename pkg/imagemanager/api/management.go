package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// ManagedImageMounter reuses the node's in-process ROFS provider. Only trusted
// runtime adapters may access this local Unix socket; it is never guest-mounted.
type ManagedImageMounter interface {
	MountOCI(context.Context, *OCIMountRequest) (*OCIMountResponse, error)
	UmountOCI(*OCIUmountRequest) error
}

type ManagementServer struct {
	server  *http.Server
	done    chan struct{}
	release func()
}

// ListenManagement is opt-in and only accepts immutable image references.
// Its private parent prevents a permission window before socket chmod.
func ListenManagement(path string, service ManagedImageMounter) (*ManagementServer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("image management socket must be an absolute clean path")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("image management socket requires a private parent directory")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	var mu sync.Mutex
	held := make(map[string]*OCIMountResponse)
	mux.HandleFunc("/oci_mount", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request OCIMountRequest
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid image request", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "unexpected trailing request", http.StatusBadRequest)
			return
		}
		ref, err := name.NewDigest(request.ImageURL)
		if err != nil || !strings.HasPrefix(ref.DigestStr(), "sha256:") {
			http.Error(w, "immutable sha256 image reference required", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		response := held[request.ImageURL]
		if response == nil {
			response, err = service.MountOCI(r.Context(), &request)
			if err == nil {
				held[request.ImageURL] = response
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	result := &ManagementServer{server: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}, done: make(chan struct{})}
	result.release = func() {
		mu.Lock()
		defer mu.Unlock()
		for image := range held {
			_ = service.UmountOCI(&OCIUmountRequest{ImageURL: image})
		}
	}
	go func() { defer close(result.done); _ = result.server.Serve(listener) }()
	return result, nil
}

func (s *ManagementServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		_ = s.server.Close()
	}
	<-s.done
	s.release()
}
