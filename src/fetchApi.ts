import { EdgeRequest, EdgeResponse, RecaptchaContext } from "./index";

export class FetchApiRequest implements EdgeRequest {
  req: Request;
  constructor(req: Request) {
    this.req = req;
  }

  get url() {
    return this.req.url;
  }

  get method() {
    return this.req.method;
  }

  get path() {
    return this.req.url;
  }

  set path(new_path: string) {
    // path is immutable within a Request, so we must create a new one.
    this.req = new Request(new_path, this.req);
  }

  addHeader(key: string, value: string): void {
    let headers = new Headers(this.req.headers);
    headers.append(key, value);
    // uses Request constructor
    this.req = new Request(this.req.url, { ...this.req, headers });
  }

  getHeader(key: string): string | null {
    return this.req.headers.get(key);
  }

  getHeaders(): Map<string, string> {
    let ret = new Map();
    this.req.headers.forEach((k, v) => {
        ret.set(k, v);
    });
    return ret;
  }
}

export class FetchApiResponse implements EdgeResponse {
  resp?: Response;
  _body?: string;
  _status: number;
  headers: Map<string, string>;

  constructor(resp: Response | string, status?: number, headers?: Record<string, string>) {
    if (typeof resp === "string") {
      this._body = resp;
      this._status = status ?? 200;
      this.headers = new Map();
      for (const [key, value] of Object.entries(headers ?? {})) {
          this.headers.set(key, value);
      }
    } else {
      this.resp = resp;
      this._status = resp.status;
      this.headers = new Map();
      for (const [key, value] of Object.entries(resp.headers ?? {})) {
        this.headers.set(key, value);
      }
    }
  }

  asResponse(): Response {
    let headers = new Headers();
    for (const [key, value] of this.headers) {
      headers.append(key, value);
    }
    return new Response(this.resp?.body ?? this._body, { ...this.resp, headers });
  }

  get status() {
    return this._status;
  }

  text(): Promise<string> {
    return this.resp?.text() ?? Promise.resolve(this._body ?? "");
  }

  json(): Promise<unknown> {
    return this.resp?.json() ?? JSON.parse(this._body ?? "{}");
  }

  addHeader(key: string, value: string): void {
    this.headers.set(key, value);
    //this.resp = new Response(this.resp.body, { ...this, headers });
  }

  getHeader(key: string): string | null {
    return this.headers.get(key) ?? null;
  }

  getHeaders(): Map<string, string> {
    return this.headers;
  }
}