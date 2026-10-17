// Package pam is a small binding to Linux-PAM for authenticating users and
// opening their sessions.
package pam

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int sintyConversation(int, struct pam_message **, struct pam_response **, uintptr_t);

static int conversation(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
	return sintyConversation(n, (struct pam_message **)msg, resp, (uintptr_t)data);
}

static struct pam_conv *new_conv(uintptr_t handle) {
	struct pam_conv *c = malloc(sizeof *c);
	if (!c) return NULL;
	c->conv = conversation;
	c->appdata_ptr = (void *)handle;
	return c;
}

static int start(const char *service, const char *user, struct pam_conv *conv, pam_handle_t **h) {
	return pam_start(service, user, conv, h);
}

static const struct pam_message *message_at(struct pam_message **msg, int i) {
	return msg[i];
}

static char *env_at(char **env, int i) {
	return env[i];
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"strings"
	"unsafe"
)

// Style is the kind of prompt PAM asks for.
type Style int

const (
	PromptEchoOff Style = C.PAM_PROMPT_ECHO_OFF
	PromptEchoOn  Style = C.PAM_PROMPT_ECHO_ON
	ErrorMsg      Style = C.PAM_ERROR_MSG
	TextInfo      Style = C.PAM_TEXT_INFO
)

// Conversation answers one PAM prompt.
type Conversation func(style Style, message string) (string, error)

// Transaction is one PAM handle.
type Transaction struct {
	handle *C.pam_handle_t
	conv   *C.struct_pam_conv
	ref    cgo.Handle
	status C.int
}

// Error carries a PAM return code.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

//export sintyConversation
func sintyConversation(n C.int, msg **C.struct_pam_message, resp **C.struct_pam_response, data C.uintptr_t) C.int {
	conv, ok := cgo.Handle(data).Value().(Conversation)
	if !ok || n <= 0 || n > 64 {
		return C.PAM_CONV_ERR
	}
	replies := (*C.struct_pam_response)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.struct_pam_response{}))))
	if replies == nil {
		return C.PAM_BUF_ERR
	}
	list := unsafe.Slice(replies, int(n))
	for i := 0; i < int(n); i++ {
		m := C.message_at(msg, C.int(i))
		answer, err := conv(Style(m.msg_style), C.GoString(m.msg))
		if err != nil {
			for j := 0; j < i; j++ {
				if list[j].resp != nil {
					C.memset(unsafe.Pointer(list[j].resp), 0, C.strlen(list[j].resp))
					C.free(unsafe.Pointer(list[j].resp))
				}
			}
			C.free(unsafe.Pointer(replies))
			return C.PAM_CONV_ERR
		}
		if Style(m.msg_style) == PromptEchoOff || Style(m.msg_style) == PromptEchoOn {
			list[i].resp = C.CString(answer)
		}
	}
	*resp = replies
	return C.PAM_SUCCESS
}

// Start begins a transaction for a service and user.
func Start(service, user string, conv Conversation) (*Transaction, error) {
	t := &Transaction{ref: cgo.NewHandle(conv)}
	t.conv = C.new_conv(C.uintptr_t(t.ref))
	if t.conv == nil {
		t.ref.Delete()
		return nil, errors.New("out of memory")
	}
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	var cu *C.char
	if user != "" {
		cu = C.CString(user)
		defer C.free(unsafe.Pointer(cu))
	}
	t.status = C.start(cs, cu, t.conv, &t.handle)
	if t.status != C.PAM_SUCCESS {
		C.free(unsafe.Pointer(t.conv))
		t.ref.Delete()
		return nil, &Error{Code: int(t.status), Message: "pam_start failed"}
	}
	return t, nil
}

func (t *Transaction) check(code C.int) error {
	t.status = code
	if code == C.PAM_SUCCESS {
		return nil
	}
	return &Error{Code: int(code), Message: C.GoString(C.pam_strerror(t.handle, code))}
}

// Authenticate runs the auth stack.
func (t *Transaction) Authenticate() error { return t.check(C.pam_authenticate(t.handle, 0)) }

// AcctMgmt runs the account stack.
func (t *Transaction) AcctMgmt() error { return t.check(C.pam_acct_mgmt(t.handle, 0)) }

// EstablishCredentials runs pam_setcred.
func (t *Transaction) EstablishCredentials() error {
	return t.check(C.pam_setcred(t.handle, C.PAM_ESTABLISH_CRED))
}

// DeleteCredentials removes credentials at the end of a session.
func (t *Transaction) DeleteCredentials() error {
	return t.check(C.pam_setcred(t.handle, C.PAM_DELETE_CRED))
}

// OpenSession runs the session stack.
func (t *Transaction) OpenSession() error { return t.check(C.pam_open_session(t.handle, 0)) }

// CloseSession closes the session stack.
func (t *Transaction) CloseSession() error { return t.check(C.pam_close_session(t.handle, 0)) }

// PutEnv sets a variable in the PAM environment.
func (t *Transaction) PutEnv(name, value string) error {
	cs := C.CString(name + "=" + value)
	defer C.free(unsafe.Pointer(cs))
	return t.check(C.pam_putenv(t.handle, cs))
}

// Env returns the PAM environment as NAME=value strings.
func (t *Transaction) Env() []string {
	list := C.pam_getenvlist(t.handle)
	if list == nil {
		return nil
	}
	var out []string
	for i := 0; ; i++ {
		p := C.env_at(list, C.int(i))
		if p == nil {
			break
		}
		entry := C.GoString(p)
		if strings.Contains(entry, "=") {
			out = append(out, entry)
		}
		C.free(unsafe.Pointer(p))
	}
	C.free(unsafe.Pointer(list))
	return out
}

// End finishes the transaction and releases it.
func (t *Transaction) End() {
	if t.handle != nil {
		C.pam_end(t.handle, t.status)
		t.handle = nil
	}
	if t.conv != nil {
		C.free(unsafe.Pointer(t.conv))
		t.conv = nil
	}
	t.ref.Delete()
}

// String describes a PAM error code.
func String(code int) string { return fmt.Sprintf("PAM error %d", code) }
