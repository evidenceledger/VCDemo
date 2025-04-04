// Copyright 2023 Jesus Ruiz. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.
package verifiernew

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
	zlog "github.com/rs/zerolog/log"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/lib/math"
	"go.starlark.net/lib/time"
	"go.starlark.net/repl"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Decision can be Authenticate or Authorize
type Decision int

const Authenticate Decision = 1
const Authorize Decision = 2

func (d Decision) String() string {
	if d == Authenticate {
		return "Authenticate"
	} else {
		return "Authorize"
	}
}

// PDP implements a simple Policy Decision Point in Starlark
type PDP struct {

	// The globals for the Starlark program
	globals              starlark.StringDict
	thread               *starlark.Thread
	authenticateFunction *starlark.Function
	authorizeFunction    *starlark.Function

	// The name of the Starlark script file.
	scriptname string
}

func NewPDP(fileName string) (*PDP, error) {

	// Create a StarLark module with our own utility functions
	var Module = &starlarkstruct.Module{
		Name: "star",
		Members: starlark.StringDict{
			"getbody": starlark.NewBuiltin("getbody", getRequestBody),
		},
	}

	// Set the global Starlark environment with required modules, including our own
	starlark.Universe["json"] = starjson.Module
	starlark.Universe["time"] = time.Module
	starlark.Universe["math"] = math.Module
	starlark.Universe["star"] = Module

	p := &PDP{}
	p.scriptname = fileName
	err := p.ParseAndCompileFile()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// ParseAndCompileFile reads a file with Starlark code and compiles it, storing the resulting global
// dictionary for later usage. In particular, the compiled module should define two functions,
// one for athentication and the second for athorisation.
// ParseAndCompileFile can be called several times and will perform a new compilation every time,
// creating a new Thread and so the old ones will never be called again and eventually will be disposed.
func (m *PDP) ParseAndCompileFile() error {
	var err error

	// The compiled program context will be stored in a new Starlark thread for each invocation
	m.thread = &starlark.Thread{
		Load:  repl.MakeLoad(),
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) },
		Name:  "exec " + m.scriptname,
	}

	// Create a predeclared environment specific for this module (empy for the moment)
	predeclared := make(starlark.StringDict)

	// Parse and execute the top-level commands in the script file
	m.globals, err = starlark.ExecFile(m.thread, m.scriptname, nil, predeclared)
	if err != nil {
		zlog.Err(err).Msg("error compiling Starlark program")
		return err
	}

	// There should be two functions: 'authenticate' and 'authorize', called at the proper moments

	m.authenticateFunction, err = m.getGlobalFunction("authenticate")
	if err != nil {
		return err
	}

	m.authorizeFunction, err = m.getGlobalFunction("authorize")
	if err != nil {
		return err
	}

	return nil

}

// getGlobalFunction retrieves a global with the specified name, requiring it to be a Callable
func (m PDP) getGlobalFunction(funcName string) (*starlark.Function, error) {

	// Check that we have the function
	f, ok := m.globals[funcName]
	if !ok {
		err := fmt.Errorf("missing definition of %s", funcName)
		zlog.Err(err).Msg("")
		return nil, err
	}

	// Check that is is a Callable
	starFunction, ok := f.(*starlark.Function)
	if !ok {
		err := fmt.Errorf("expected a Callable but got %v", f.Type())
		zlog.Err(err).Str("type", f.Type()).Msg("expected a Callable")
		return nil, err
	}

	return starFunction, nil
}

// TakeAuthnDecision is called when a decision should be taken for either Athentication or Authorization.
// The type of decision to evaluate is passed in the Decision argument. The rest of the arguments contain the information required
// for the decision. They are:
// - the Verifiable Credential with the information from the caller needed for the decision
// - the protected resource that the caller identified in the Credential wants to access
func (m PDP) TakeAuthnDecision(decision Decision, r *http.Request, credential string, protectedResource string) (bool, error) {
	var err error
	debug := true

	zlog.Info().Str("decision", decision.String()).Msg("TakeAuthnDecision")
	fmt.Println("Credential", credential)

	// In development, parse and compile the script on every request
	if debug {
		err := m.ParseAndCompileFile()
		if err != nil {
			return false, err
		}
	}

	// Create the input arguments
	// httpRequest := StarDictFromFiberRequest(c)
	httpRequest, err := StarDictFromHttpRequest(r)
	if err != nil {
		return false, err
	}
	credentialArgument := starlark.String(credential)
	protectedArgument := starlark.String(protectedResource)

	// Build the arguments to the StarLark function
	var args starlark.Tuple
	args = append(args, httpRequest)
	args = append(args, credentialArgument)
	args = append(args, protectedArgument)

	// Call the corresponding function in the Starlark Thread
	var result starlark.Value
	if decision == Authenticate {
		// Call the 'authenticate' funcion
		result, err = starlark.Call(m.thread, m.authenticateFunction, args, nil)
	} else {
		// Call the 'authorize' function
		result, err = starlark.Call(m.thread, m.authorizeFunction, args, nil)
	}

	if err != nil {
		return false, err
	}

	// Check that the value returned is of the correct type (boolean)
	resultType := result.Type()
	if resultType != "bool" {
		err := fmt.Errorf("function returned wrong type: %v", resultType)
		return false, err
	}

	// Return the value as a Go boolean
	return bool(result.(starlark.Bool).Truth()), nil

}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (m PDP) HttpHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	debug := true

	zlog.Info().Msg("in JSONRPC handler")

	// Check that this is a JSON request
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "invalid content type", http.StatusForbidden)
	}

	// Read and decode the body from the request and store in thread locals in case we need it later
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var msg jsonrpcMessage
	err = json.Unmarshal(bytes, &msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if msg.Version != "2.0" {
		http.Error(w, "invalid JSON-RPC version", http.StatusBadRequest)
	}
	if len(msg.Method) == 0 {
		http.Error(w, "JSON-RPC method not specified", http.StatusBadRequest)
	}
	m.thread.SetLocal("jsonmessage", m)

	// In development, parse and compile the script on every request
	if debug {
		err := m.ParseAndCompileFile()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	m.thread.SetLocal("httprequest", r)

	// Create the input argument
	req, err := StarDictFromHttpRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	req.SetKey(starlark.String("jsonrpc_method"), starlark.String(msg.Method))

	// Call the already compiled 'authenticate' funcion
	var args starlark.Tuple
	args = append(args, req)
	res, err := starlark.Call(m.thread, m.authenticateFunction, args, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Check that the value returned is of the correct type
	resultType := res.Type()
	if resultType != "string" {
		err := fmt.Errorf("authenticate function returned wrong type: %v", resultType)
		zlog.Err(err).Msg("")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Return the value
	user := res.(starlark.String).GoString()

	if len(user) > 0 {
		w.Write([]byte("Authenticated"))
	} else {
		w.Write([]byte("Forbidden"))
	}

}

func getRequestBody(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {

	// Get the current HTTP request being processed
	r := thread.Local("httprequest")
	request, ok := r.(*http.Request)
	if !ok {
		return starlark.None, fmt.Errorf("no request found in thread locals")
	}

	// Read the body from the request and store in thread locals in case we need it later
	bytes, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	thread.SetLocal("requestbody", bytes)

	// Resturn string for the Starlark script
	body := starlark.String(bytes)

	return body, nil
}

func StarDictFromHttpRequest(request *http.Request) (*starlark.Dict, error) {

	dd := &starlark.Dict{}

	dd.SetKey(starlark.String("method"), starlark.String(request.Method))
	dd.SetKey(starlark.String("url"), starlark.String(request.URL.String()))
	dd.SetKey(starlark.String("path"), starlark.String(request.URL.Path))
	dd.SetKey(starlark.String("query"), getDictFromValues(request.URL.Query()))

	dd.SetKey(starlark.String("host"), starlark.String(request.Host))
	dd.SetKey(starlark.String("content_length"), starlark.MakeInt(int(request.ContentLength)))
	dd.SetKey(starlark.String("headers"), getDictFromHeaders(request.Header))

	return dd, nil
}

func getDictFromValues(values map[string][]string) *starlark.Dict {
	dict := &starlark.Dict{}
	for key, values := range values {
		dict.SetKey(starlark.String(key), getSkylarkList(values))
	}
	return dict
}

func getDictFromHeaders(headers http.Header) *starlark.Dict {
	dict := &starlark.Dict{}
	for key, values := range headers {
		dict.SetKey(starlark.String(key), getSkylarkList(values))
	}
	return dict
}

func getSkylarkList(values []string) *starlark.List {
	list := &starlark.List{}
	for _, v := range values {
		list.Append(starlark.String(v))
	}
	return list
}

// *** Specific for Fiber

func StarDictFromFiberRequest(c *fiber.Ctx) *starlark.Dict {
	dd := &starlark.Dict{}

	// Set simple values
	dd.SetKey(starlark.String("method"), starlark.String(c.Method()))
	dd.SetKey(starlark.String("host"), starlark.String(c.Hostname()))
	dd.SetKey(starlark.String("remoteip"), starlark.String(c.IP()))
	dd.SetKey(starlark.String("url"), starlark.String(c.OriginalURL()))
	dd.SetKey(starlark.String("path"), starlark.String(c.Path()))
	dd.SetKey(starlark.String("protocol"), starlark.String(c.Protocol()))

	// Request headers
	starHeaders := &starlark.Dict{}
	headers := c.GetReqHeaders()
	for key, value := range headers {
		starHeaders.SetKey(starlark.String(key), starlark.String(value))
	}
	dd.SetKey(starlark.String("headers"), starHeaders)

	// Path Parameters
	starParams := &starlark.Dict{}
	pathParams := c.AllParams()
	for key, value := range pathParams {
		starParams.SetKey(starlark.String(key), starlark.String(value))
	}
	dd.SetKey(starlark.String("pathparams"), starParams)

	// Query Parameters
	starQueries := &starlark.Dict{}
	queries := c.Queries()
	for key, value := range queries {
		starQueries.SetKey(starlark.String(key), starlark.String(value))
	}
	dd.SetKey(starlark.String("queryparams"), starQueries)

	return dd
}
