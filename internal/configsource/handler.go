package configsource

import "net/http"

// Handler sirve cada request con el http.Handler del snapshot vigente en el
// momento en que el request EMPIEZA. Current() se llama una sola vez: si en la
// mitad del request se publica otra config, este request no se entera y
// termina con la que tomó. El siguiente request ya usa la nueva.
//
// Es genérico para que el Value del snapshot pueda ser un tipo concreto (como
// *apps.Router, que además sabe qué apps hay) y no solo un http.Handler.
func Handler[T http.Handler](r *Reloader[T]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Current().Value.ServeHTTP(w, req)
	})
}
