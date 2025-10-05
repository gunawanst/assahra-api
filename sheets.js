import { google } from 'googleapis';

const getAuth = ({ client_email, private_key }) => {
  return new google.auth.JWT({
    email: client_email,
    key: private_key,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
};

export class SheetsRepo {
  constructor({ spreadsheetId, client_email, private_key, tables }) {
    this.spreadsheetId = spreadsheetId;
    this.tables = tables;
    this.auth = getAuth({ client_email, private_key });
    this.sheets = google.sheets({ version: 'v4', auth: this.auth });
  }

  async readTable(name) {
    const range = `${name}!A:Z`;
    const res = await this.sheets.spreadsheets.values.get({
      spreadsheetId: this.spreadsheetId,
      range,
    });
    const values = res.data.values || [];
    if (values.length === 0) return [];
    const [headers, ...rows] = values;
    const trimmed = headers.map(h => String(h || '').trim());
    return rows
      .filter(r => (r.join('') || '').trim() !== '')
      .map(r => Object.fromEntries(trimmed.map((h, i) => [h, r[i]])));
  }

  async appendRow(name, arr) {
    await this.sheets.spreadsheets.values.append({
      spreadsheetId: this.spreadsheetId,
      range: `${name}!A:Z`,
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [arr] },
    });
  }

  // convenience getters
  async getAdmins()    { return this.readTable(this.tables.admins); }
  async getTeachers()  { return this.readTable(this.tables.teachers); }
  async getClasses()   { return this.readTable(this.tables.classes); }
  async getAttendance(){ return this.readTable(this.tables.attendance); }

  async addAdmin({ email, salt, hash, role }) {
    return this.appendRow(this.tables.admins, [email, salt, hash, role || 'admin', new Date().toISOString()]);
  }
}
