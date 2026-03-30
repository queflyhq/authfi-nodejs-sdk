import { RequestHandler } from 'express';

interface AuthFIConfig {
  tenant: string;
  apiKey: string;
  apiUrl?: string;
  applicationId?: string;
  autoSync?: boolean;
  jwksRefreshInterval?: number;
}

interface Claims {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string;
  roles: string[];
  permissions: string[];
  tenant_id: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  iat: number;
  exp: number;
  iss: string;
}

interface AuthFIClient {
  require(...permissions: string[]): RequestHandler;
  requireRole(...roles: string[]): RequestHandler;
  authenticate(): RequestHandler;
  verifyToken(token: string): Promise<Claims>;
  start(): Promise<void>;
  registerPermission(name: string, description?: string): void;
  syncPermissions(): Promise<void>;
}

declare function authfi(config: AuthFIConfig): AuthFIClient;
export = authfi;

declare global {
  namespace Express {
    interface Request {
      user?: Claims;
    }
  }
}
