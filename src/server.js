import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
// Small, compressed employee photos may be sent as data URLs.
app.use(express.json({ limit: '8mb' }));

const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
mongoose.set('autoIndex', false);

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, lowercase: true, trim: true, default: undefined },
  phone: { type: String, trim: true, default: undefined },
  passwordHash: { type: String, select: false },
  role: { type: String, enum: ['admin', 'employee'], default: 'employee' },
  active: { type: Boolean, default: true },
  // monthlySalary is the salary used for payroll. dailyWage is retained only for old records.
  monthlySalary: { type: Number, default: 0, min: 0 },
  salaryHistory: [{ month: { type: String, required: true }, amount: { type: Number, min: 0, required: true } }],
  dailyWage: { type: Number, default: 0 },
  photoUrl: { type: String, default: '' }
}, { timestamps: true });
userSchema.index({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string' } } });
userSchema.index({ phone: 1 }, { unique: true, partialFilterExpression: { phone: { $type: 'string' } } });
const User = mongoose.model('User', userSchema);

const attendanceSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: String, required: true },
  status: { type: String, enum: ['Present', 'Absent', 'Half-day', 'On Leave'], required: true },
  arrivalTime: { type: String, default: '' },
  leavingTime: { type: String, default: '' },
  workingMinutes: { type: Number, default: 0, min: 0 },
  isLate: { type: Boolean, default: false },
  note: { type: String, default: '' },
  markedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
attendanceSchema.index({ employee: 1, date: 1 }, { unique: true });
const Attendance = mongoose.model('Attendance', attendanceSchema);

const ledgerSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: String, required: true },
  // Advance/Payment remain accepted for compatibility with older app versions.
  type: { type: String, enum: ['Taken', 'Given', 'Advance', 'Payment', 'Bonus', 'Deduction', 'Other'], required: true },
  amount: { type: Number, required: true, min: 0.01 },
  reason: { type: String, required: true, trim: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const Ledger = mongoose.model('Ledger', ledgerSchema);

const leaveSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fromDate: { type: String, required: true },
  toDate: { type: String, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewNote: { type: String, default: '' }
}, { timestamps: true });
const Leave = mongoose.model('Leave', leaveSchema);

function tokenFor(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    if (!raw) throw new Error();
    req.auth = jwt.verify(raw, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Please log in again.' });
  }
}
const adminOnly = (req, res, next) => req.auth?.role === 'admin'
  ? next()
  : res.status(403).json({ message: 'Admin access required.' });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const publicUser = u => ({
  id: u._id,
  name: u.name,
  email: u.email || '',
  phone: u.phone || '',
  role: u.role,
  active: u.active,
  monthlySalary: Number(u.monthlySalary || 0),
  photoUrl: u.photoUrl || '',
  createdAt: u.createdAt
});

app.get('/api/health', asyncRoute(async (_req, res) => {
  res.json({ api: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
}));

app.post('/api/auth/admin-login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = await User.findOne({ email, role: 'admin', active: true }).select('+passwordHash');
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: 'Invalid admin email or password.' });
  }
  res.json({ token: tokenFor(user), user: publicUser(user) });
}));

app.post('/api/auth/employee-login', asyncRoute(async (req, res) => {
  const phone = String(req.body.phone || '').trim();
  const password = String(req.body.password || '');
  const user = await User.findOne({ phone, role: 'employee', active: true }).select('+passwordHash');
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: 'Invalid phone number or password.' });
  }
  res.json({ token: tokenFor(user), user: publicUser(user) });
}));

app.get('/api/auth/me', auth, asyncRoute(async (req, res) => {
  const user = await User.findById(req.auth.sub);
  if (!user) return res.status(404).json({ message: 'Account not found.' });
  res.json({ user: publicUser(user) });
}));

app.get('/api/employees', auth, asyncRoute(async (req, res) => {
  const query = req.auth.role === 'admin' ? { role: 'employee' } : { _id: req.auth.sub, role: 'employee' };
  const users = await User.find(query).sort({ name: 1 });
  res.json({ employees: users.map(publicUser) });
}));

app.post('/api/employees', auth, adminOnly, asyncRoute(async (req, res) => {
  const { name, phone, monthlySalary = 0, password, photoUrl = '' } = req.body;
  const cleanName = String(name || '').trim();
  const cleanPhone = String(phone || '').trim();
  if (!cleanName || !cleanPhone) {
    return res.status(400).json({ message: 'Name and phone are required.' });
  }
  const existingPhone = await User.findOne({ phone: cleanPhone, role: 'employee' }).select('_id name phone');
  if (existingPhone) {
    return res.status(409).json({
      code: 'DUPLICATE_PHONE',
      message: `Phone number ${cleanPhone} already belongs to ${existingPhone.name}. Find that employee in the list below and use View details or Edit details.`,
      existingEmployee: publicUser(existingPhone)
    });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ message: 'Employee password must be at least 8 characters.' });
  }
  if (!Number.isFinite(Number(monthlySalary)) || Number(monthlySalary) < 0) {
    return res.status(400).json({ message: 'Enter a valid monthly salary.' });
  }
  const user = await User.create({
    name: cleanName, phone: cleanPhone, monthlySalary: Number(monthlySalary) || 0,
    salaryHistory: [{ month: new Date().toISOString().slice(0, 7), amount: Number(monthlySalary) || 0 }],
    passwordHash: await bcrypt.hash(password, 12), photoUrl: String(photoUrl || ''), role: 'employee'
  });
  res.status(201).json({ employee: publicUser(user) });
}));

app.delete('/api/employees/:id', auth, adminOnly, asyncRoute(async (req, res) => {
  const employee = await User.findOne({ _id: req.params.id, role: 'employee' }).select('_id name');
  if (!employee) return res.status(404).json({ message: 'Employee not found.' });

  // Permanently remove employee-owned records so attendance, ledger and leave
  // queries do not retain orphaned references to a deleted employee.
  await Promise.all([
    Attendance.deleteMany({ employee: employee._id }),
    Ledger.deleteMany({ employee: employee._id }),
    Leave.deleteMany({ employee: employee._id }),
  ]);
  await User.deleteOne({ _id: employee._id, role: 'employee' });

  res.json({ message: `Employee ${employee.name} and their attendance, transactions, and leave records were deleted.` });
}));

app.patch('/api/employees/:id', auth, adminOnly, asyncRoute(async (req, res) => {
  const allowed = ['name', 'phone', 'monthlySalary', 'photoUrl', 'active'];
  const update = {};
  for (const key of allowed) if (req.body[key] !== undefined) update[key] = req.body[key];
  if (update.monthlySalary !== undefined && (!Number.isFinite(Number(update.monthlySalary)) || Number(update.monthlySalary) < 0)) {
    return res.status(400).json({ message: 'Enter a valid monthly salary.' });
  }
  if (req.body.password !== undefined && req.body.password !== '') {
    if (typeof req.body.password !== 'string' || req.body.password.length < 8) {
      return res.status(400).json({ message: 'Employee password must be at least 8 characters.' });
    }
    update.passwordHash = await bcrypt.hash(req.body.password, 12);
  }
  let employee = await User.findOne({ _id: req.params.id, role: 'employee' });
  if (!employee) return res.status(404).json({ message: 'Employee not found.' });
  if (update.phone !== undefined) {
    update.phone = String(update.phone).trim();
    if (!update.phone) return res.status(400).json({ message: 'Phone number is required.' });
    const duplicate = await User.findOne({ phone: update.phone, role: 'employee', _id: { $ne: employee._id } }).select('name phone');
    if (duplicate) return res.status(409).json({ code: 'DUPLICATE_PHONE', message: `This phone number already belongs to ${duplicate.name}. Please use a different number.` });
  }
  if (update.name !== undefined) update.name = String(update.name).trim();
  if (update.name !== undefined && !update.name) return res.status(400).json({ message: 'Name is required.' });
  if (update.monthlySalary !== undefined) {
    const effectiveMonth = new Date().toISOString().slice(0, 7);
    const history = Array.isArray(employee.salaryHistory) ? employee.salaryHistory : [];
    const sameMonth = history.findIndex(item => item.month === effectiveMonth);
    const snapshot = { month: effectiveMonth, amount: Number(update.monthlySalary) };
    if (sameMonth >= 0) history[sameMonth] = snapshot; else history.push(snapshot);
    employee.salaryHistory = history;
  }
  Object.assign(employee, update);
  await employee.save();
  res.json({ employee: publicUser(employee) });
}));

app.get('/api/attendance', auth, asyncRoute(async (req, res) => {
  const filter = {};
  if (req.auth.role !== 'admin') filter.employee = req.auth.sub;
  if (req.query.date) filter.date = String(req.query.date);
  if (req.query.month && /^\d{4}-\d{2}$/.test(String(req.query.month))) filter.date = { $gte: `${req.query.month}-01`, $lte: `${req.query.month}-31` };
  const items = await Attendance.find(filter).populate('employee', 'name phone monthlySalary')
    .sort({ date: -1, createdAt: -1 }).limit(req.query.date ? 500 : (req.query.month ? 10000 : 100));
  res.json({ attendance: items });
}));

// Attendance is admin-managed; employees can only view their own attendance.
app.post('/api/attendance', auth, adminOnly, asyncRoute(async (req, res) => {
  const { employeeId, date, status, arrivalTime = '', leavingTime = '', note = '' } = req.body;
  const validStatuses = ['Present', 'Absent', 'Half-day', 'On Leave'];
  if (!employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(String(date || '')) || !validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Employee, valid date and attendance status are required.' });
  }
  if (['Present', 'Half-day'].includes(status) && !String(arrivalTime).trim()) return res.status(400).json({ message: 'Arrival time is required for Present or Half-day.' });
  const employee = await User.findOne({ _id: employeeId, role: 'employee', active: true });
  if (!employee) return res.status(404).json({ message: 'Employee not found.' });
  const toMinutes = value => {
    const match = String(value || '').trim().match(/^(\d{1,2}):(\d{2})(?:\s*(AM|PM))?$/i);
    if (!match) return null;
    let hour = Number(match[1]), minute = Number(match[2]);
    if (minute > 59 || hour > 23) return null;
    if (match[3]) hour = hour % 12 + (match[3].toUpperCase() === 'PM' ? 12 : 0);
    return hour * 60 + minute;
  };
  const arrival = toMinutes(arrivalTime), leaving = toMinutes(leavingTime);
  const workingMinutes = ['Present', 'Half-day'].includes(status) && arrival !== null && leaving !== null ? Math.max(0, (leaving < arrival ? leaving + 1440 : leaving) - arrival) : 0;
  const isLate = ['Present', 'Half-day'].includes(status) && arrival !== null && arrival > 540; // 9:00 AM default start
  const item = await Attendance.findOneAndUpdate({ employee: employeeId, date }, {
    status, arrivalTime: ['Present', 'Half-day'].includes(status) ? String(arrivalTime) : '',
    leavingTime: ['Present', 'Half-day'].includes(status) ? String(leavingTime || '') : '',
    workingMinutes, isLate, note, markedBy: req.auth.sub
  }, { upsert: true, new: true, runValidators: true });
  res.json({ attendance: item });
}));

app.get('/api/ledger', auth, asyncRoute(async (req, res) => {
  const filter = req.auth.role === 'admin' ? {} : { employee: req.auth.sub };
  if (req.query.employeeId && req.auth.role === 'admin') filter.employee = req.query.employeeId;
  if (req.query.month && /^\d{4}-\d{2}$/.test(String(req.query.month))) {
    filter.date = { $gte: `${req.query.month}-01`, $lte: `${req.query.month}-31` };
  }
  const items = await Ledger.find(filter).populate('employee', 'name phone').sort({ date: -1, createdAt: -1 }).limit(1000);
  res.json({ entries: items });
}));

app.post('/api/ledger', auth, adminOnly, asyncRoute(async (req, res) => {
  const { employeeId, date, type, amount, reason } = req.body;
  if (!employeeId || !/^\d{4}-\d{2}-\d{2}$/.test(String(date || '')) ||
      !['Bonus', 'Deduction'].includes(type) ||
      !(Number(amount) > 0) || !String(reason || '').trim()) {
    return res.status(400).json({ message: 'Choose Bonus or Deduction and enter employee, date, amount and reason.' });
  }
  const employee = await User.findOne({ _id: employeeId, role: 'employee' });
  if (!employee) return res.status(404).json({ message: 'Employee not found.' });
  const entry = await Ledger.create({ employee: employeeId, date, type, amount: Number(amount), reason: String(reason).trim(), createdBy: req.auth.sub });
  res.status(201).json({ entry });
}));

// Monthly summary: positive balance means the business still owes the employee;
// negative balance means the employee has taken more than earned and owes the business.
app.get('/api/payroll', auth, asyncRoute(async (req, res) => {
  const month = /^\d{4}-\d{2}$/.test(String(req.query.month || ''))
    ? String(req.query.month)
    : new Date().toISOString().slice(0, 7);
  const [year, monthNumber] = month.split('-').map(Number);
  if (monthNumber < 1 || monthNumber > 12) return res.status(400).json({ message: 'Invalid month.' });
  const monthStart = `${month}-01`;
  const monthEnd = `${month}-${String(new Date(year, monthNumber, 0).getDate()).padStart(2, '0')}`;
  const employees = await User.find(req.auth.role === 'admin'
    ? { role: 'employee', active: true }
    : { _id: req.auth.sub, role: 'employee', active: true }).sort({ name: 1 });
  const results = [];
  const monthIndex = value => Number(value.slice(0, 4)) * 12 + Number(value.slice(5, 7));
  for (const employee of employees) {
    const createdMonth = employee.createdAt ? employee.createdAt.toISOString().slice(0, 7) : month;
    const salaryHistory = (employee.salaryHistory || []).slice().sort((a, b) => String(a.month).localeCompare(String(b.month)));
    // Salary changes take effect in the month they are saved, so old months are not rewritten.
    const salaryFor = targetMonth => {
      if (targetMonth < createdMonth) return 0;
      let amount = 0;
      for (const snapshot of salaryHistory) {
        if (String(snapshot.month) <= targetMonth) amount = Number(snapshot.amount || 0);
      }
      return amount;
    };
    let earnedBefore = 0;
    if (month >= createdMonth) {
      for (let cursor = createdMonth; cursor < month; ) {
        earnedBefore += salaryFor(cursor);
        const [cy, cm] = cursor.split('-').map(Number);
        cursor = cm === 12 ? `${cy + 1}-01` : `${cy}-${String(cm + 1).padStart(2, '0')}`;
      }
    }
    const salary = salaryFor(month);
    const ledger = await Ledger.find({ employee: employee._id, date: { $lte: monthEnd } }).sort({ date: 1 }).lean();
    const totalsBefore = { taken: 0, given: 0, bonus: 0, deduction: 0 };
    const totalsMonth = { taken: 0, given: 0, bonus: 0, deduction: 0 };
    for (const item of ledger) {
      const key = item.type === 'Taken' || item.type === 'Advance' ? 'taken'
        : item.type === 'Given' || item.type === 'Payment' ? 'given'
        : item.type === 'Bonus' ? 'bonus' : item.type === 'Deduction' ? 'deduction' : null;
      if (!key) continue;
      const target = item.date < monthStart ? totalsBefore : totalsMonth;
      target[key] += Number(item.amount || 0);
    }
    const openingBalance = earnedBefore + totalsBefore.bonus - totalsBefore.deduction - totalsBefore.taken - totalsBefore.given;
    const monthNet = salary + totalsMonth.bonus - totalsMonth.deduction - totalsMonth.taken - totalsMonth.given;
    const closingBalance = openingBalance + monthNet;
    results.push({
      employee: { id: employee._id, name: employee.name, phone: employee.phone || '' }, month, monthlySalary: salary,
      taken: totalsMonth.taken, given: totalsMonth.given, bonus: totalsMonth.bonus, deduction: totalsMonth.deduction,
      openingBalance, monthBalance: monthNet, closingBalance,
      salaryRemaining: Math.max(0, monthNet), employeeOwes: Math.max(0, -closingBalance), businessOwes: Math.max(0, closingBalance)
    });
  }
  res.json({ month, payroll: results });
}));

app.get('/api/leaves', auth, asyncRoute(async (req, res) => {
  const filter = req.auth.role === 'admin' ? {} : { employee: req.auth.sub };
  const items = await Leave.find(filter).populate('employee', 'name phone').sort({ createdAt: -1 });
  res.json({ leaves: items });
}));

app.post('/api/leaves', auth, asyncRoute(async (req, res) => {
  const { fromDate, toDate, reason } = req.body;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(fromDate || '')) || !/^\d{4}-\d{2}-\d{2}$/.test(String(toDate || '')) ||
      toDate < fromDate || !String(reason || '').trim()) {
    return res.status(400).json({ message: 'Enter valid leave dates and a reason.' });
  }
  const item = await Leave.create({ employee: req.auth.sub, fromDate, toDate, reason: String(reason).trim() });
  res.status(201).json({ leave: item });
}));

app.patch('/api/leaves/:id/review', auth, adminOnly, asyncRoute(async (req, res) => {
  const { status, reviewNote = '' } = req.body;
  if (!['Approved', 'Rejected'].includes(status)) return res.status(400).json({ message: 'Status must be Approved or Rejected.' });
  const item = await Leave.findByIdAndUpdate(req.params.id, { status, reviewNote, reviewedBy: req.auth.sub }, { new: true })
    .populate('employee', 'name phone');
  if (!item) return res.status(404).json({ message: 'Leave request not found.' });
  res.json({ leave: item });
}));

app.get('/api/dashboard', auth, asyncRoute(async (req, res) => {
  if (req.auth.role !== 'admin') return res.json({ role: 'employee' });
  const today = new Date().toISOString().slice(0, 10);
  const [employees, present, pendingLeaves, ledgerEntries] = await Promise.all([
    User.countDocuments({ role: 'employee', active: true }),
    Attendance.countDocuments({ date: today, status: 'Present' }),
    Leave.countDocuments({ status: 'Pending' }),
    Ledger.countDocuments({})
  ]);
  res.json({ employees, present, pendingLeaves, ledgerEntries, date: today });
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err?.code === 11000) {
    const field = Object.keys(err.keyPattern || {})[0];
    const value = err.keyValue?.[field];
    const message = field === 'phone' ? `Phone number ${value ?? ''} is already assigned to another employee. Refresh the employee list and open that employee to view or edit details.`
      : field === 'email' ? `Email ${value ?? ''} is already assigned to another account.`
      : field === 'employee' && err.keyPattern?.date ? 'Attendance for this employee and date already exists. Refresh the attendance list to edit the saved record.'
      : 'A record with these details already exists. Refresh the list and open the existing record.';
    return res.status(409).json({ code: 'DUPLICATE_RECORD', field, value, message });
  }
  res.status(500).json({ message: 'Server error. Check backend logs.' });
});

async function migrateUserIndexes() {
  const indexes = await User.collection.indexes();
  for (const name of ['email_1', 'phone_1']) {
    if (indexes.some(index => index.name === name)) {
      await User.collection.dropIndex(name);
      console.log(`Removed legacy index: ${name}`);
    }
  }
  await User.createIndexes();
  await Attendance.createIndexes();
  await Ledger.createIndexes();
  await Leave.createIndexes();
  console.log('Database indexes are ready');
}

async function main() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing. Configure backend/.env.');
  if (!JWT_SECRET) throw new Error('JWT_SECRET is missing. Configure backend/.env.');
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('MongoDB Atlas connected successfully');
  await migrateUserIndexes();
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
    const existing = await User.findOne({ email, role: 'admin' });
    if (!existing) {
      await User.create({ name: 'Administrator', email, role: 'admin', passwordHash: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12) });
      console.log(`Initial admin created for ${email}`);
    }
  }
  app.listen(PORT, '0.0.0.0', () => console.log(`API listening on 0.0.0.0:${PORT}\nHealth: http://localhost:${PORT}/api/health`));
}
main().catch(err => { console.error('Backend startup failed:', err.message); process.exit(1); });
