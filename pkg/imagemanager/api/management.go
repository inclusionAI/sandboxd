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

type RegistryMetadataReader interface {
	Metadata(context.Context, string, string, bool) ([]byte, string, error)
}

type ManagementServer struct {
	server  *http.Server
	done    chan struct{}
	release func()
	cancel  context.CancelFunc
	active  sync.WaitGroup
	closing sync.Mutex
	closed  bool
	once    sync.Once
}

// ListenManagement is opt-in and only accepts immutable image references.
// Its private parent prevents a permission window before socket chmod.
func ListenManagement(path string, service ManagedImageMounter, readers ...RegistryMetadataReader) (*ManagementServer, error) {
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
	if len(readers) > 0 && readers[0] != nil {
		mux.HandleFunc("/registry_metadata", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			var request struct {
				Reference string `json:"reference"`
				Kind      string `json:"kind"`
				Insecure  bool   `json:"insecure"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, "invalid metadata request", http.StatusBadRequest)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				http.Error(w, "unexpected trailing request", http.StatusBadRequest)
				return
			}
			ref, err := name.NewDigest(request.Reference)
			if err != nil || !strings.HasPrefix(ref.DigestStr(), "sha256:") || (request.Kind != "manifests" && request.Kind != "blobs") {
				http.Error(w, "immutable OCI metadata reference required", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()
			data, mediaType, err := readers[0].Metadata(ctx, request.Reference, request.Kind, request.Insecure)
			if err != nil {
				http.Error(w, "Registry metadata request failed", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "media_type": mediaType})
		})
	}
	var mu sync.Mutex
	var operations imageOperationLocks
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
		unlock, err := operations.lock(r.Context(), request.ImageURL)
		if err != nil {
			http.Error(w, "image request canceled", http.StatusRequestTimeout)
			return
		}
		defer unlock()
		mu.Lock()
		response := held[request.ImageURL]
		mu.Unlock()
		if response == nil {
			response, err = service.MountOCI(r.Context(), &request)
			if err == nil {
				mu.Lock()
				held[request.ImageURL] = response
				mu.Unlock()
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	serverCtx, cancel := context.WithCancel(context.Background())
	result := &ManagementServer{done: make(chan struct{}), cancel: cancel}
	result.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.closing.Lock()
		if result.closed {
			result.closing.Unlock()
			http.Error(w, "image service closing", http.StatusServiceUnavailable)
			return
		}
		result.active.Add(1)
		result.closing.Unlock()
		defer result.active.Done()
		mux.ServeHTTP(w, r)
	}), BaseContext: func(net.Listener) context.Context { return serverCtx }, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
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
	s.once.Do(func() {
		s.closing.Lock()
		s.closed = true
		s.closing.Unlock()
		s.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			_ = s.server.Close()
		}
		<-s.done
		// Closing sockets alone does not join handlers. Their preparation/rollback
		// must finish before releasing service-owned image leases.
		s.active.Wait()
		s.release()
	})
}
