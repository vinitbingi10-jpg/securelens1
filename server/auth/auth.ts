import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { db, hashPassword, verifyPassword, User } from '../db/database.js';

// Active tokens in-memory mapping: token -> { userId, expiresAt }
const sessions = new Map<string, { userId: string; expiresAt: number }>();

export function generateToken(userId: string): string {
  const token = `sl_tok_${crypto.randomBytes(32).toString('hex')}`;
  // Session expires in 7 days
  sessions.set(token, {
    userId,
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
  });
  return token;
}

export function revokeToken(token: string): void {
  sessions.delete(token);
}

export function getUserFromToken(token?: string): User | null {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }

  const user = db.findUserById(session.userId);
  if (!user || !user.isActive) {
    return null;
  }
  return user;
}

export interface AuthenticatedRequest extends Request {
  user?: User;
}

export function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.query.token && typeof req.query.token === 'string') {
    token = req.query.token;
  }

  if (token) {
    const user = getUserFromToken(token);
    if (user) {
      req.user = user;
    }
  }

  next();
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      error: 'Authentication required. Please sign in to access this resource.',
    });
    return;
  }
  next();
}
