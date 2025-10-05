import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const ROUNDS = 10; // cost bcrypt, cepat & aman

export const hashPw = async (password) => {
  return bcrypt.hash(password, ROUNDS);
};

export const verifyPw = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

export const makeJwt = (email, secret, hours = 12) => {
  return jwt.sign(
    { sub: email.toLowerCase().trim(), role: 'admin' },
    secret,
    { expiresIn: `${hours}h` }
  );
};

export const verifyJwt = (token, secret, roleNeeded = 'admin') => {
  try {
    const decoded = jwt.verify(token, secret);
    if (roleNeeded && decoded.role !== roleNeeded) {
      return { ok:false, error:'Forbidden' };
    }
    return { ok:true, email: decoded.sub, role: decoded.role, exp: decoded.exp };
  } catch (e) {
    return { ok:false, error: e.message || 'Invalid token' };
  }
};
