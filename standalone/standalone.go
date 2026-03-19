package standalone

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/fullstorydev/grpcui"
	"github.com/fullstorydev/grpcui/internal/resources/standalone"
)

const csrfCookieName = "_grpcui_csrf_token"

const csrfHeaderName = "x-grpcui-csrf-token"

// Handler returns an HTTP handler that provides a fully-functional gRPC web
// UI, including the main index (with the HTML form), all needed CSS and JS
// assets, and the handlers that provide schema metadata and perform RPC
// invocations. The HTML index, CSS, and JS files can be customized and
// augmented with opts.
//
// All RPC invocations are sent to the given channel. The given target is shown
// in the header of the web UI, to show the user where their requests are being
// sent. The given methods enumerate all supported RPC methods, and the given
// files enumerate all known protobuf (for enumerating all supported message
// types, to support the use of google.protobuf.Any messages).
//
// The returned handler expects to serve resources from "/". If it will instead
// be handling a sub-path (e.g. handling "/rpc-ui/") then use http.StripPrefix.
// serverTarget pairs a display address with its live gRPC channel.
type serverTarget struct {
	target string
	conn   grpcdynamic.Channel
}

// stateChecker is implemented by *grpc.ClientConn.
type stateChecker interface {
	GetState() connectivity.State
	Connect()
	WaitForStateChange(ctx context.Context, sourceState connectivity.State) bool
}

func handlerInternal(connectedMethods []grpcui.ConnectedMethod, methods []*desc.MethodDescriptor, files []*desc.FileDescriptor, servers []serverTarget, opts ...HandlerOption) http.Handler {
	targets := make([]string, len(servers))
	for i, s := range servers {
		targets[i] = s.target
	}
	target := strings.Join(targets, ", ")
	uiOpts := &handlerOptions{
		indexTmpl:      defaultIndexTemplate,
		css:            grpcui.WebFormSampleCSS(),
		cssPublic:      true,
		gRPCurlOptions: nil,
	}
	for _, o := range opts {
		o.apply(uiOpts)
	}

	var mux http.ServeMux

	// Add embedded resources bundled in standalone package TOC
	for _, assetName := range standalone.AssetNames() {
		// the index file will be handled separately
		if assetName == standalone.IndexTemplateName {
			continue
		}
		resourcePath := "/" + assetName
		handle(&mux, newResource(resourcePath, standalone.MustAsset(assetName), "", true))
	}

	// Add resources from WebFormPackage
	handle(&mux, newResource("/grpc-web-form.js", grpcui.WebFormScript(), "text/javascript; charset=UTF-8", true))
	handle(&mux, newResource("/grpc-web-form.css", uiOpts.css, "text/css; charset=UTF-8", uiOpts.cssPublic))

	// Add optional resources to mux
	for _, res := range uiOpts.addlServedResources() {
		handle(&mux, res)
	}

	// Add the index page (not bundled in standalone)
	formOpts := grpcui.WebFormOptions{
		DefaultMetadata: uiOpts.defaultMetadata,
		Debug:           uiOpts.debug,
		GRPCurlOptions:  uiOpts.gRPCurlOptions,
	}
	webFormHTML := grpcui.WebFormContentsWithOptions("invoke", "metadata", target, methods, formOpts)
	indexContents := getIndexContents(uiOpts.indexTmpl, target, webFormHTML, uiOpts.tmplResources)
	indexResource := newResource("/", indexContents, "text/html; charset=utf-8", false)
	indexResource.MustRevalidate = true
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			indexResource.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	invokeOpts := grpcui.InvokeOptions{
		ExtraMetadata:   uiOpts.extraMetadata,
		PreserveHeaders: uiOpts.preserveHeaders,
		EmitDefaults:    uiOpts.emitDefaults,
		Verbosity:       uiOpts.invokeVerbosity,
	}
	rpcInvokeHandler := http.StripPrefix("/invoke", grpcui.RPCInvokeHandlerForServers(connectedMethods, invokeOpts))
	mux.HandleFunc("/invoke/", func(w http.ResponseWriter, r *http.Request) {
		// CSRF protection
		c, _ := r.Cookie(csrfCookieName)
		h := r.Header.Get(csrfHeaderName)
		if c == nil || c.Value == "" || c.Value != h {
			http.Error(w, "incorrect CSRF token", http.StatusUnauthorized)
			return
		}
		rpcInvokeHandler.ServeHTTP(w, r)
	})

	rpcMetadataHandler := grpcui.RPCMetadataHandler(methods, files)
	mux.Handle("/metadata", rpcMetadataHandler)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		type targetStatus struct {
			Target string `json:"target"`
			OK     bool   `json:"ok"`
		}
		results := make([]targetStatus, len(servers))
		var wg sync.WaitGroup
		for i, srv := range servers {
			wg.Add(1)
			go func(idx int, s serverTarget) {
				defer wg.Done()
				ok := false
				if sc, canCheck := s.conn.(stateChecker); canCheck {
					// Trigger a reconnect attempt if the connection is idle.
					sc.Connect()
					state := sc.GetState()
					// If still connecting, wait up to 2s for it to settle.
					if state == connectivity.Connecting || state == connectivity.Idle {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						sc.WaitForStateChange(ctx, state)
						state = sc.GetState()
					}
					ok = state == connectivity.Ready
				}
				results[idx] = targetStatus{Target: s.target, OK: ok}
			}(i, srv)
		}
		wg.Wait()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(results)
	})

	mux.HandleFunc("/examples", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		if len(uiOpts.examples) > 0 {
			w.Write(uiOpts.examples)
		} else {
			w.Write([]byte("[]"))
		}
	})

	// make sure we always have a csrf token cookie
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(csrfCookieName); err != nil {
			tokenBytes := make([]byte, 32)
			if _, err := rand.Read(tokenBytes); err != nil {
				http.Error(w, "failed to create CSRF token", http.StatusInternalServerError)
				return
			}
			c := &http.Cookie{
				Name:  csrfCookieName,
				Value: base64.RawURLEncoding.EncodeToString(tokenBytes),
			}
			http.SetCookie(w, c)
		}

		mux.ServeHTTP(w, r)
	})
}

// ServerConfig describes one gRPC server to include in a multi-server UI.
type ServerConfig struct {
	// Target is the address displayed in the UI (e.g. "localhost:50051").
	Target string
	// Channel is the connection to this server.
	Channel grpcdynamic.Channel
	// Methods enumerates the RPC methods available on this server.
	Methods []*desc.MethodDescriptor
	// Files enumerates all proto files known for this server (used for
	// google.protobuf.Any resolution).
	Files []*desc.FileDescriptor
}

// HandlerMulti is like Handler but accepts methods from multiple gRPC servers.
// All servers' services are merged into a single UI. Each RPC invocation is
// automatically routed to the server the method was discovered from.
func HandlerMulti(servers []ServerConfig, opts ...HandlerOption) http.Handler {
	var connectedMethods []grpcui.ConnectedMethod
	var allFiles []*desc.FileDescriptor
	var allMethods []*desc.MethodDescriptor
	srvTargets := make([]serverTarget, 0, len(servers))
	seenFiles := map[string]bool{}

	for _, srv := range servers {
		srvTargets = append(srvTargets, serverTarget{target: srv.Target, conn: srv.Channel})
		for _, m := range srv.Methods {
			connectedMethods = append(connectedMethods, grpcui.ConnectedMethod{Desc: m, Conn: srv.Channel})
			allMethods = append(allMethods, m)
		}
		for _, f := range srv.Files {
			if !seenFiles[f.GetName()] {
				seenFiles[f.GetName()] = true
				allFiles = append(allFiles, f)
			}
		}
	}

	return handlerInternal(connectedMethods, allMethods, allFiles, srvTargets, opts...)
}

// Handler returns an HTTP handler that provides a fully-functional gRPC web UI
// for a single server. See HandlerMulti for multi-server support.
func Handler(ch grpcdynamic.Channel, target string, methods []*desc.MethodDescriptor, files []*desc.FileDescriptor, opts ...HandlerOption) http.Handler {
	connected := make([]grpcui.ConnectedMethod, len(methods))
	for i, m := range methods {
		connected[i] = grpcui.ConnectedMethod{Desc: m, Conn: ch}
	}
	return handlerInternal(connected, methods, files, []serverTarget{{target: target, conn: ch}}, opts...)
}

var defaultIndexTemplate = template.Must(
	template.New("index.html").
		Funcs(template.FuncMap{
			"splitTarget": func(t string) []string {
				parts := strings.Split(t, ", ")
				result := make([]string, 0, len(parts))
				for _, p := range parts {
					if p = strings.TrimSpace(p); p != "" {
						result = append(result, p)
					}
				}
				return result
			},
		}).
		Parse(string(standalone.IndexTemplate())),
)

func getIndexContents(tmpl *template.Template, target string, webFormHTML []byte, addlResources []*resource) []byte {
	addlHTML := make([]template.HTML, 0, len(addlResources))
	for _, res := range addlResources {
		tag := res.AsHTMLTag()
		if tag != "" {
			addlHTML = append(addlHTML, template.HTML(tag))
		}
	}
	data := WebFormContainerTemplateData{
		Target:          target,
		WebFormContents: template.HTML(webFormHTML),
		AddlResources:   addlHTML,
	}

	var indexBuf bytes.Buffer
	if err := tmpl.Execute(&indexBuf, data); err != nil {
		panic(err)
	}
	return indexBuf.Bytes()
}

type resource struct {
	Path           string
	Len            int
	Open           func(string) (io.ReadCloser, error)
	ContentType    string
	ETag           string
	Public         bool
	MustRevalidate bool
}

func newResource(uriPath string, data []byte, contentType string, public bool) *resource {
	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(uriPath))
	}
	return &resource{
		Path: uriPath,
		Open: func(_ string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		Len:         len(data),
		ContentType: contentType,
		ETag:        computeETag(data),
		Public:      public,
	}
}

func newDeferredResource(uriPath string, open func() (io.ReadCloser, error), contentType string) *resource {
	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(uriPath))
	}
	return &resource{
		Path: uriPath,
		Open: func(_ string) (io.ReadCloser, error) {
			return open()
		},
		ContentType: contentType,
	}
}

func newDeferredResourceFolder(uriPath string, open func(string) (io.ReadCloser, error)) *resource {
	return &resource{
		Path: uriPath + "/",
		Open: func(filename string) (io.ReadCloser, error) {
			return open(filename)
		},
	}
}

func handle(mux *http.ServeMux, res *resource) {
	mux.Handle(res.Path, res)
	if withoutSlash := strings.TrimSuffix(res.Path, "/"); withoutSlash != res.Path {
		// if res.Path is a folder, return a 404 if the base directory is
		// requested (default behavior is a redirect to URI with trailing slash)
		mux.Handle(withoutSlash, http.NotFoundHandler())
	}
}

func (res *resource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, err := filepath.Rel(res.Path, r.URL.Path)
	var reader io.ReadCloser
	if err == nil {
		reader, err = res.Open(name)
	}
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, fmt.Sprintf("failed to open file %q: %v", r.URL.Path, err), http.StatusInternalServerError)
		}
		return
	}
	defer func() {
		_ = reader.Close()
	}()

	etag := r.Header.Get("If-None-Match")
	if etag != "" && etag == res.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	ct := res.ContentType
	if ct == "" {
		ct = mime.TypeByExtension(path.Ext(r.URL.Path))
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	var cacheSuffix string
	if res.MustRevalidate {
		cacheSuffix = "must-revalidate"
	} else {
		cacheSuffix = "max-age=3600"
	}
	if res.Public {
		w.Header().Set("Cache-Control", "public, "+cacheSuffix)
	} else {
		w.Header().Set("Cache-Control", "private, "+cacheSuffix)
	}
	if res.ETag != "" {
		w.Header().Set("ETag", res.ETag)
	}
	if res.Len > 0 {
		w.Header().Set("Content-Length", strconv.Itoa(res.Len))
	}
	_, _ = io.Copy(w, reader)
}

// AsHTMLTag returns an HTML string corresponding to a tag that would load this resource (by inspecting ContentType).
// Only supports "text/javascript" and "text/css" for ContentType.
// Returns empty string if we do not support the ContentType.
func (res *resource) AsHTMLTag() string {
	if strings.HasPrefix(res.ContentType, "text/javascript") {
		return fmt.Sprintf("<script src=\"%s\"></script>", strings.TrimLeft(res.Path, "/"))
	} else if strings.HasPrefix(res.ContentType, "text/css") {
		return fmt.Sprintf("<link rel=\"stylesheet\" href=\"%s\">", strings.TrimLeft(res.Path, "/"))
	}

	// Fallthrough as a no-op
	return ""
}

func computeETag(contents []byte) string {
	hasher := sha256.New()
	hasher.Write(contents)
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

// HandlerViaReflection tries to query the provided connection for all services
// and methods supported by the server, and constructs a handler to serve the UI.
//
// The handler has the same properties as the one returned by Handler.
func HandlerViaReflection(ctx context.Context, cc grpc.ClientConnInterface, target string, opts ...HandlerOption) (http.Handler, error) {
	m, err := grpcui.AllMethodsViaReflection(ctx, cc)
	if err != nil {
		return nil, err
	}

	f, err := grpcui.AllFilesViaReflection(ctx, cc)
	if err != nil {
		return nil, err
	}

	return Handler(cc, target, m, f, opts...), nil
}
