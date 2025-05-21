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
  json(): Promise<any>;
  addHeader(key: string, value: string): void;
  getHeader(key: string): string | null;
  getHeaders(): Map<string, string>;
  readonly status: number;
}
