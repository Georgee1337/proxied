### Reverse Proxy with Caching and Rate Limiting

This is a simple reverse proxy server with caching and rate limiting functionality implemented in Go. The server reads the target domain configurations from a JSON file, and then proxies incoming requests to the appropriate target based on the Host header of the request. The server also caches images to improve performance and rate limits incoming requests to avoid overloading the server.

## Dependencies
This server depends on the following packages:

`golang.org/x/time/rate`

## Usage

```json
[
    {
        "domain": "example.com",
        "ip": "127.0.0.1",
        "port": "8080"
    },
    {
        "domain": "example.org",
        "ip": "127.0.0.1",
        "port": "8081"
    }
]
```

Each object in the array represents a target domain configuration, with domain being the target domain, ip being the IP address of the target server, and port being the port number of the target server.

**To run the server, simply compile and run the code:**
```shell
go build
```

The server listens on port 80 by default, but you can change this by modifying the last line of the main function.


# Features

### Caching
This server caches images to improve performance. When a request for an image is received, the server checks if the image is already in the cache. If the image is in the cache and has not expired, the server serves the image from the cache instead of forwarding the request to the target server.

### Rate Limiting
This server rate limits incoming requests to avoid overloading the server. The rate limit is set to 10 requests per second per IP address. If a client exceeds the rate limit, the server responds with a 429 Too Many Requests error.
