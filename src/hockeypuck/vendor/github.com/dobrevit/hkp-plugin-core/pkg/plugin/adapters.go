// Package plugin adapters for compatibility
package plugin

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// HTTPHandlerAdapter adapts a standard http.HandlerFunc to httprouter.Handle
// This allows plugins to use standard http handlers with httprouter-based hosts
func HTTPHandlerAdapter(handler http.HandlerFunc) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Store httprouter params in request context if needed
		// For now, just call the handler
		handler(w, r)
	}
}

// HTTPHandlerWithParamsAdapter adapts a handler that needs access to httprouter params
// Example usage:
//   host.RegisterHandler("/user/:id", HTTPHandlerWithParamsAdapter(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
//       userID := ps.ByName("id")
//       // ... handle request
//   }))
func HTTPHandlerWithParamsAdapter(handler func(http.ResponseWriter, *http.Request, httprouter.Params)) httprouter.Handle {
	return httprouter.Handle(handler)
}

// WrapStandardHandler is a convenience method that wraps a standard http.HandlerFunc
// for use with httprouter-based plugin hosts
func WrapStandardHandler(handler http.HandlerFunc) httprouter.Handle {
	return HTTPHandlerAdapter(handler)
}