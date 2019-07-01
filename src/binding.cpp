#include <iostream>
#include <nan.h>
#include "ocsp.h"

using namespace std;
using namespace v8;
using namespace Nan;

class OCSPWorker : public AsyncWorker {
 public:
  OCSPWorker(Callback *callback, string cert, string issuer, string header, string url)
    : AsyncWorker(callback) {
        this->cert = cert;
        this->issuer = issuer;
        this->header = header;
        this->url = url;
    }
  ~OCSPWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
        int timeout = 5;
        this->result = verifyOCSP(this->cert.c_str(), this->issuer.c_str(), this->header.c_str(), this->url.c_str(), timeout);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {
    Nan::HandleScope scope;

    Local<Object> value = New<Object>();
    Nan::Set(value, New("status").ToLocalChecked(), New(this->result.status));
    if (this->result.statusStr == NULL) {
        Nan::Set(value, New("statusStr").ToLocalChecked(), Null());
    } else {
        Nan::Set(value, New("statusStr").ToLocalChecked(), New(this->result.statusStr).ToLocalChecked());
    }
    Nan::Set(value, New("reason").ToLocalChecked(), New(this->result.reason));
    if (this->result.reasonStr == NULL) {
        Nan::Set(value, New("reasonStr").ToLocalChecked(), Null());
    } else {
        Nan::Set(value, New("reasonStr").ToLocalChecked(), New(this->result.reasonStr).ToLocalChecked());
    }
    if (this->result.thisupdStr == NULL) {
        Nan::Set(value, New("thisUpdate").ToLocalChecked(), Null());
    } else {
        Nan::Set(value, New("thisUpdate").ToLocalChecked(), New(this->result.thisupdStr).ToLocalChecked());
    }
    if (this->result.nextupdStr == NULL) {
        Nan::Set(value, New("nextUpdate").ToLocalChecked(), Null());
    } else {
        Nan::Set(value, New("nextUpdate").ToLocalChecked(), New(this->result.nextupdStr).ToLocalChecked());
    }
    if (!(this->result.revokedStr == NULL)) {
        Nan::Set(value, New("revocationTime").ToLocalChecked(), New(this->result.revokedStr).ToLocalChecked());
    }

    Local<Value> error = Null();
    if (!(this->result.errorStr == NULL)) {
        error = Nan::New(this->result.errorStr).ToLocalChecked();
    }

    Local<Value> argv[] = {
        error,
        value
    };

    Nan::Call(callback->GetFunction(), Nan::GetCurrentContext()->Global(), 2, argv);
  }

  private:
    string cert;
    string issuer;
    string header;
    string url;
    ocspCheck result;
};

NAN_METHOD(GetRevocationStatusAsync) {
    Nan::MaybeLocal<String> maybeCert = Nan::To<String>(info[0]);
    Nan::MaybeLocal<String> maybeIssuer = Nan::To<String>(info[1]);
    Nan::MaybeLocal<String> maybeHeader = Nan::To<String>(info[2]);
    Nan::MaybeLocal<String> maybeUrl = Nan::To<String>(info[3]);
    Callback *callback = new Nan::Callback(Nan::To<Function>(info[4]).ToLocalChecked());
    if (maybeCert.IsEmpty() || maybeIssuer.IsEmpty() || maybeHeader.IsEmpty() || maybeUrl.IsEmpty()) {
        return Nan::ThrowError(Nan::New("Missing args").ToLocalChecked());
    }
    Local<String> cert_local = maybeCert.ToLocalChecked();
    Local<String> issuer_local = maybeIssuer.ToLocalChecked();
    Local<String> header_local = maybeHeader.ToLocalChecked();
    Local<String> url_local = maybeUrl.ToLocalChecked();
    AsyncQueueWorker(new OCSPWorker(callback, *Nan::Utf8String(cert_local), *Nan::Utf8String(issuer_local), *Nan::Utf8String(header_local), *Nan::Utf8String(url_local)));
}

NAN_MODULE_INIT(Init) {
  Nan::Set(target, Nan::New("getRevocationStatusAsync").ToLocalChecked(),
      Nan::GetFunction(Nan::New<FunctionTemplate>(GetRevocationStatusAsync)).ToLocalChecked());
}

NODE_MODULE(ocsp, Init);
