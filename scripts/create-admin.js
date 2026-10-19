import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
const schema = new mongoose.Schema({name:String,email:{type:String,unique:true},passwordHash:String,role:String,active:Boolean},{timestamps:true});
const User=mongoose.model('User',schema);
const [email,password,name='Administrator']=process.argv.slice(2);
if(!email||!password){console.error('Usage: npm run create-admin -- admin@example.com StrongPassword "Admin Name"');process.exit(1);}
if(!process.env.MONGODB_URI){console.error('Set MONGODB_URI in backend/.env first.');process.exit(1);}
await mongoose.connect(process.env.MONGODB_URI);
const normalized=email.toLowerCase();
await User.findOneAndUpdate({email:normalized},{name,email:normalized,passwordHash:await bcrypt.hash(password,12),role:'admin',active:true},{upsert:true,new:true,setDefaultsOnInsert:true});
console.log(`Admin account ready: ${normalized}`);await mongoose.disconnect();
