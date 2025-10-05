import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

import { SheetsRepo } from './sheets.js';
import { hashPw, verifyPw, makeJwt, verifyJwt } from './auth.js';
import { isEmail, isYm, buildSlip } from './utils.js';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== ENV =====
const {
  PORT = 8787,
  JWT_SECRET,
  SPREADSHEET_ID,
  SA_CLIENT_EMAIL,
  SA_PRIVATE_KEY,
  SHEETS_ADMINS = 'admins',
  SHEETS_TEACHERS = 'teachers',
  SHEETS_CLASSES = 'classes',
  SHEETS_ATTENDANCE = 'attendance',
} = process.env;

if (!JWT_SECRET)  console.warn('WARN: JWT_SECRET belum diisi');
if (!SPREADSHEET_ID) console.warn('WARN: SPREADSHEET_ID belum diisi');

const repo = new SheetsRepo({
  spreadsheetId: SPREADSHEET_ID,
  client_email: SA_CLIENT_EMAIL,
  private_key: SA_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  tables: {
    admins: SHEETS_ADMINS,
    teachers: SHEETS_TEACHERS,
    classes: SHEETS_CLASSES,
    attendance: SHEETS_ATTENDANCE,
  }
});

// ===== Helpers =====
const ok   = (res, obj) => res.json({ ok:true, ...obj });
const fail = (res, error) => res.json({ ok:false, error: String(error) });

// ====== ACTION ROUTES (kompatibel) ======

// GET ?action=adminStatus
app.get('/', async (req, res) => {
  const { action } = req.query;
  try{
    if (action === 'adminstatus'){
      const admins = await repo.getAdmins();
      return ok(res, { has_admin: admins.length > 0 });
    }

    if (action === 'listteachers'){
      const data = await repo.getTeachers();
      const out = data.map(t => ({
        teacher_id: String(t.teacher_id ?? '').trim(),
        name: t.name ?? ''
      }));
      return ok(res, { data: out });
    }

    if (action === 'getslip'){
      const { admin_token, teacher_id, month } = req.query;
      // verify token
      const v = verifyJwt(String(admin_token||''), JWT_SECRET, 'admin');
      if (!v.ok) return fail(res, v.error);

      if (!teacher_id || !isYm(month)) return fail(res, 'Missing/invalid teacher_id or month (YYYY-MM)');

      const [classes, attendance] = await Promise.all([
        repo.getClasses(),
        repo.getAttendance(),
      ]);

      const slip = buildSlip(teacher_id, month, classes, attendance);
      return ok(res, { data: slip });
    }

    return fail(res, 'Unknown action');
  }catch(err){ return fail(res, err.message || err); }
});

// POST action=adminLogin | adminCreate
app.post('/', async (req, res) => {
  const action = String(req.query.action || req.body.action || '').toLowerCase();
  try{
    if (action === 'adminlogin'){
      const email = String(req.body.email || '').trim().toLowerCase();
      const password = String(req.body.password || '');

      if (!isEmail(email) || !password) return fail(res, 'Email atau password salah.');

      const admins = await repo.getAdmins();
      const user = admins.find(a => String(a.email || '').trim().toLowerCase() === email);
      if (!user) return fail(res, 'Email atau password salah.');

      const okPw = await verifyPw(password, String(user.hash || ''));
      if (!okPw) return fail(res, 'Email atau password salah.');

      const token = makeJwt(email, JWT_SECRET, 12);
      return ok(res, { email, token });
    }

    if (action === 'admincreate'){
      const email = String(req.body.email || '').trim().toLowerCase();
      const password = String(req.body.password || '');
      const adminTokenOpt = String(req.body.admin_token || '');

      if (!isEmail(email)) return fail(res, 'Email tidak valid.');
      if (!password || password.length < 8) return fail(res, 'Password minimal 8 karakter.');

      const admins = await repo.getAdmins();
      if (admins.length > 0){
        // jika sudah ada admin, creation perlu admin_token yang valid
        const v = verifyJwt(adminTokenOpt, JWT_SECRET, 'admin');
        if (!v.ok) return fail(res, v.error);
      }
      const existing = admins.find(a => String(a.email || '').trim().toLowerCase() === email);
      if (existing) return fail(res, 'Email sudah terdaftar.');

      const hash = await hashPw(password);
      await repo.addAdmin({ email, salt: '(bcrypt)', hash, role: 'admin' });

      const token = makeJwt(email, JWT_SECRET, 12);
      return ok(res, { email, token });
    }

    return fail(res, 'Unknown action');
  }catch(err){ return fail(res, err.message || err); }
});

// Healthcheck
app.get('/health', (req,res)=>res.json({ ok:true, ts: Date.now() }));

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});
