// Authenticated context is never carried in a caller-controlled header.
const contexts = new WeakMap();
export const bindVerifiedRequest = (request, claims) => contexts.set(request, Object.freeze(claims));
export const boundRequestClaims = request => contexts.get(request);
