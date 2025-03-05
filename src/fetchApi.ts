export type EdgeRequestInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

export interface EdgeRequest {
  readonly method: string;
  url: string;
  addHeader(key: string, value: string): void;
  getHeader(key: string): string | null;
  getHeaders(): Map<string, string>;
  getBodyText(): Promise<string>;
  getBodyJson(): Promise<any>;
}
export type EdgeResponseInit = {
  readonly status?: number;
  readonly headers?: Record<string, string>;
};

export interface EdgeResponse {
  text(): Promise<string>;
  json(): Promise<unknown>;
  addHeader(key: string, value: string): void;
  getHeader(key: string): string | null;
  getHeaders(): Map<string, string>;
  readonly status: number;
}

export class FetchApiRequest implements EdgeRequest {
  req: Request;
  constructor(req: Request | string) {
    if (typeof req === "string") {
      this.req = new Request(req);
    } else {
      this.req = req;
    }
  }

  get url() {
    return this.req.url;
  }

  set url(new_url: string) {
    // path is immutable within a Request, so we must create a new one.
    this.req = new Request(new_url, this.req);
  }

  get method() {
    return this.req.method;
  }

  addHeader(key: string, value: string): void {
    let headers = new Headers(this.req.headers);
    headers.append(key, value);
    // uses Request constructor
    this.req = new Request(this.req.url, {
      method: this.req.method,
      headers,
      body: this.req.body,
      credentials: this.req.credentials,
      mode: this.req.mode,
      redirect: this.req.redirect,
      cache: this.req.cache,
    });
  }

  getHeader(key: string): string | null {
    return this.req.headers.get(key);
  }

  getHeaders(): Map<string, string> {
    let ret = new Map();
    this.req.headers.forEach((v, k) => {
      ret.set(k, v);
    });
    return ret;
  }

  async getBodyText(): Promise<string> {
    return this.req.clone().text();
  }

  async getBodyJson(): Promise<unknown> {
    return this.req.clone().json();
  }

  asRequest(): Request {
    return this.req;
  }
}

export class FetchApiResponse implements EdgeResponse {
  resp: Response;
  headers: Map<string, string>;

  constructor(resp: Response | string, options?: EdgeResponseInit) {
    if (typeof resp === "string") {
      const resp_headers = new Headers();
      this.headers = new Map();
      for (const [key, value] of Object.entries(options?.headers ?? {})) {
        this.headers.set(key, value);
        resp_headers.append(key, value);
      }
      this.resp = new Response(resp, { status: options?.status ?? 200, headers: resp_headers });
    } else {
      this.resp = resp;
      this.headers = new Map();
      resp.headers.forEach((v, k) => {
        this.headers.set(k.toLowerCase(), v);
      });
    }
  }

  asResponse(): Response {
    let headers = new Headers();
    for (const [key, value] of this.headers.entries()) {
      headers.append(key.toLowerCase(), value);
    }
    return new Response(this.resp?.body, { status: this.resp?.status, statusText: this.resp?.statusText, headers });
  }

  get status() {
    return this.resp?.status;
  }

  text(): Promise<string> {
    return this.resp?.text();
  }

  json(): Promise<unknown> {
    return this.resp?.json();
  }

  addHeader(key: string, value: string): void {
    this.headers.set(key.toLowerCase(), value);
  }

  getHeader(key: string): string | null {
    return this.headers.get(key.toLowerCase()) ?? null;
  }

  getHeaders(): Map<string, string> {
    return this.headers;
  }
}
