import jwt from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';

const jwksClient = new JwksClient({
  jwksUri:
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com',
  cache: true,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
});

export interface FirebaseTokenPayload {
  uid: string;
  email?: string;
  name?: string;
}

export async function verifyFirebaseIdToken(
  idToken: string,
  projectId: string
): Promise<FirebaseTokenPayload | null> {
  if (!idToken || !projectId) return null;

  try {
    const decoded = jwt.decode(idToken, { complete: true });
    if (!decoded || typeof decoded === 'string' || !decoded.header?.kid) return null;

    const key = await jwksClient.getSigningKey(decoded.header.kid);
    const publicKey = key.getPublicKey();

    const payload = jwt.verify(idToken, publicKey, {
      algorithms: ['RS256'],
      audience: projectId,
      issuer: `https://securetoken.google.com/${projectId}`,
    }) as jwt.JwtPayload;

    const uid = (payload.sub ?? payload.uid) as string | undefined;
    if (!uid) return null;

    return {
      uid,
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
    };
  } catch {
    return null;
  }
}
