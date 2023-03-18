package main

import (
	"golang.org/x/time/rate"

	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type DomainConfig struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   string `json:"port"`
}

type CacheItem struct {
	Content       []byte
	ContentType   string
	CreationTime  time.Time
}

const cacheTTL = 5 * time.Minute

var rateLimiters = make(map[string]*rate.Limiter)
const rateLimit = 10

var cache = struct {
	sync.RWMutex
	items map[string]*CacheItem
}{items: make(map[string]*CacheItem)}

func main() {
	configFile := "config.json"
	configs, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			log.Printf("Incoming request: %s %s", req.Method, req.URL.String())

			domain := req.Host
			if domain == "" {
				log.Printf("Request does not have a Host header")
				return
			}

			target, ok := configs[domain]
			if !ok {
				log.Printf("Unknown domain: %s", domain)
				req.Header.Set("X-Proxy-Error", "host not in config")
				return
			}

			targetURL, err := url.Parse("http://" + target.IP + ":" + target.Port)
			if err != nil {
				log.Printf("Error parsing target URL: %v", err)
				return
			}

			log.Printf("Forwarding request to: %s", targetURL.String())

			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
		},
		ModifyResponse: func(res *http.Response) error {
			if isImage(res) {
				cacheResponse(res)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			log.Printf("Error handling request: %v", err)
			if req.Header.Get("X-Proxy-Error") == "host not in config" {
				http.Error(w, "host not in config", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		clientIP := req.RemoteAddr
		limiter := getRateLimiter(clientIP)
	
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded: %s", clientIP)
			return
		}
	
		if isImageRequest(req) {
			if serveFromCache(w, req) {
				return
			}
		}
		proxy.ServeHTTP(w, req)
	})
	

	log.Printf("Proxy server listening on :80")
	log.Fatal(http.ListenAndServe(":80", http.DefaultServeMux))
}

func loadConfig(filename string) (map[string]DomainConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var domainConfigs []DomainConfig
	err = json.Unmarshal(data, &domainConfigs)
	if err != nil {
		return nil, err
	}

	configs := make(map[string]DomainConfig)
	for _, config := range domainConfigs {
		configs[config.Domain] = config
	}

	log.Printf("Loaded %d domain configurations", len(configs))
	return configs, nil
}

func isImageRequest(req *http.Request) bool {
	return req.Method == http.MethodGet && req.Header.Get("Accept") == "image/webp,image/apng,image/*,*/*;q=0.8"
}

func isImage(res *http.Response) bool {
	contentType := res.Header.Get("Content-Type")
	return contentType != "" && (contentType[:5] == "image")
}

func cacheResponse(res *http.Response) {
	url := res.Request.URL.String()
	contentType := res.Header.Get("Content-Type")

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return
	}

	err = res.Body.Close()
	if err != nil {
		log.Printf("Error closing response body: %v", err)
		return
	}

	res.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	item := &CacheItem{
		Content:       bodyBytes,
		ContentType:   contentType,
		CreationTime:  time.Now(),
	}

	cache.Lock()
	cache.items[url] = item
	cache.Unlock()

	log.Printf("Cached response for: %s", url)
}

func serveFromCache(w http.ResponseWriter, req *http.Request) bool {
	cache.RLock()
	item, found := cache.items[req.URL.String()]
	cache.RUnlock()

	if !found {
		return false
	}

	if time.Since(item.CreationTime) > cacheTTL {
		cache.Lock()
		delete(cache.items, req.URL.String())
		cache.Unlock()

		log.Printf("Cache item expired: %s", req.URL.String())
		return false
	}

	w.Header().Set("Content-Type", item.ContentType)
	w.Write(item.Content)

	log.Printf("Served from cache: %s", req.URL.String())
	return true
}

func getRateLimiter(ip string) *rate.Limiter {
	limiter, exists := rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rateLimit), rateLimit)
		rateLimiters[ip] = limiter
	}
	return limiter
}
