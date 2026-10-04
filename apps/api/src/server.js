import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.set('trust proxy', 1);
app.use(helmet());
const allowedOrigins = new Set([
  'https://qr-restaurant-os.onrender.com',
  'http://localhost:5173',
  process.env.WEB_ORIGIN
].filter(Boolean));

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('CORS origin not allowed'));
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));

const JWT_SECRET = process.env.JWT_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!JWT_SECRET) console.warn('JWT_SECRET is not configured');
const orderSchema = z.object({
  items: z.array(z.object({
    menu_item_id: z.string().uuid(),
    quantity: z.number().int().min(1).max(20),
    size: z.enum(['small','large']).default('small')
  })).min(1).max(50)
});

function setSessionCookie(res, token) {
  res.cookie('customer_session', token, {
    httpOnly: true, secure: true,
    sameSite: 'none', path: '/', maxAge: 12 * 60 * 60 * 1000
  });
}

async function customerSession(req) {
  const token = req.headers['x-customer-session'] || req.cookies?.customer_session;
  if (!token) return null;
  const { data, error } = await supabase
    .from('customer_sessions')
    .select('id,restaurant_id,table_id,session_token,expires_at,restaurant_tables!inner(label,active),restaurants!inner(name)')
    .eq('session_token', token)
    .gt('expires_at', new Date().toISOString())
    .eq('restaurant_tables.active', true)
    .maybeSingle();
  if (error || !data) return null;
  return {
    session_id: data.id,
    restaurant_id: data.restaurant_id,
    table_id: data.table_id,
    table_label: data.restaurant_tables.label,
    restaurant_name: data.restaurants.name
  };
}

app.get('/health', async (_, res) => {
  const { error } = await supabase.from('restaurants').select('id').limit(1);
  if (error) return res.status(503).json({ ok: false, database: 'unavailable' });
  res.json({ ok: true, service: 'qr-restaurant-api', database: 'supabase' });
});

app.get('/api/table/:shortCode',async(req,res)=>{try{const{data:table}=await supabase.from('restaurant_tables').select('id,label,active,public_token,restaurants!inner(id,name,slug,status,logo_url,cover_image_url,phone,address,google_maps_url,instagram_url,facebook_url,default_language)').eq('short_code',req.params.shortCode).eq('active',true).eq('restaurants.status','active').maybeSingle();if(!table)return res.status(404).json({error:'Invalid table QR'});const restaurant=table.restaurants;const{data:items,error}=await supabase.from('menu_items').select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order').eq('restaurant_id',restaurant.id).eq('is_available',true).order('category').order('sort_order');if(error)throw error;res.json({restaurant_id:restaurant.id,restaurant_name:restaurant.name,restaurant_slug:restaurant.slug,restaurant_branding:{logo_url:restaurant.logo_url,cover_image_url:restaurant.cover_image_url,phone:restaurant.phone,address:restaurant.address,google_maps_url:restaurant.google_maps_url,instagram_url:restaurant.instagram_url,facebook_url:restaurant.facebook_url,default_language:restaurant.default_language},table_id:table.id,table_label:table.label,table_code:req.params.shortCode,items})}catch(e){console.error(e);res.status(500).json({error:'Server error'})}});

app.get('/api/menu/:restaurantSlug/:tableToken', async (req, res) => {
  try {
    const { data: restaurant, error: restaurantError } = await supabase
      .from('restaurants')
      .select('id,name,slug')
      .eq('slug', req.params.restaurantSlug)
      .maybeSingle();
    if (restaurantError || !restaurant) return res.status(404).json({ error: 'Invalid restaurant' });

    const { data: table, error: tableError } = await supabase
      .from('restaurant_tables')
      .select('id,label,active')
      .eq('restaurant_id', restaurant.id)
      .eq('public_token', req.params.tableToken)
      .eq('active', true)
      .maybeSingle();
    if (tableError || !table) return res.status(404).json({ error: 'Invalid table QR' });

    const { data: items, error: menuError } = await supabase
      .from('menu_items')
      .select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order')
      .eq('restaurant_id', restaurant.id)
      .eq('is_available', true)
      .order('category')
      .order('sort_order');
    if (menuError) throw menuError;

    res.json({
      restaurant_id: restaurant.id,
      restaurant_name: restaurant.name,
      restaurant_slug: restaurant.slug,
      table_id: table.id,
      table_label: table.label,
      items
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

function sessionJoinCode(token){return crypto.createHmac('sha256',JWT_SECRET||'table-session-secret').update('join:'+token).digest('hex').slice(0,6).toUpperCase()}

app.post('/api/session',async(req,res)=>{try{const body=z.object({restaurantSlug:z.string().min(1).max(100).optional(),tableToken:z.string().min(20).max(100).optional(),tableCode:z.string().min(4).max(20).optional(),customerName:z.string().trim().min(2).max(60)}).refine(v=>v.tableCode||(v.restaurantSlug&&v.tableToken),{message:'Invalid table reference'}).parse(req.body);let restaurant=null,table=null;if(body.tableCode){const{data}=await supabase.from('restaurant_tables').select('id,active,restaurant_id,restaurants!inner(id,slug)').eq('short_code',body.tableCode).eq('active',true).maybeSingle();table=data;restaurant=data?.restaurants||null}else{const{data}=await supabase.from('restaurants').select('id').eq('slug',body.restaurantSlug).maybeSingle();restaurant=data||null;if(restaurant){const{data:t}=await supabase.from('restaurant_tables').select('id,active').eq('restaurant_id',restaurant.id).eq('public_token',body.tableToken).eq('active',true).maybeSingle();table=t}}if(!restaurant)return res.status(404).json({error:'Invalid restaurant'});if(!table)return res.status(404).json({error:'Invalid table QR'});const existingToken=req.headers['x-customer-session']||req.cookies?.customer_session;if(existingToken){const{data:existing}=await supabase.from('customer_sessions').select('id,session_token,customer_name').eq('session_token',existingToken).eq('restaurant_id',restaurant.id).eq('table_id',table.id).gt('expires_at',new Date().toISOString()).maybeSingle();if(existing){setSessionCookie(res,existing.session_token);return res.json({ok:true,existing:true,join_code:sessionJoinCode(existing.session_token),customer_name:existing.customer_name||body.customerName})}}const{data:active,error:activeError}=await supabase.from('customer_sessions') .select('id,session_token,customer_name').eq('restaurant_id',restaurant.id).eq('table_id',table.id).gt('expires_at',new Date().toISOString()).order('created_at',{ascending:false}).limit(1);if(activeError)throw activeError;if(active?.length)return res.status(409).json({error:'Table is already in use',code:'TABLE_OCCUPIED',table_label:table.label,join_required:true});const token=crypto.randomBytes(32).toString('hex'),expires=new Date(Date.now()+12*60*60*1000).toISOString();const{error}=await supabase.from('customer_sessions').insert({restaurant_id:restaurant.id,table_id:table.id,session_token:token,expires_at:expires,customer_name:body.customerName});if(error)throw error;setSessionCookie(res,token);res.json({ok:true,join_code:sessionJoinCode(token),customer_name:body.customerName})}catch(e){console.error(e);res.status(400).json({error:'Unable to start table session'})}});

app.post('/api/session/join',async(req,res)=>{try{const body=z.object({restaurantSlug:z.string().min(1).max(100).optional(),tableToken:z.string().min(20).max(100).optional(),tableCode:z.string().min(4).max(20).optional(),joinCode:z.string().regex(/^[A-Z0-9]{6}$/)}).refine(v=>v.tableCode||(v.restaurantSlug&&v.tableToken),{message:'Invalid table reference'}).parse(req.body);let restaurant=null,table=null;if(body.tableCode){const{data}=await supabase.from('restaurant_tables').select('id,active,restaurant_id,restaurants!inner(id,slug)').eq('short_code',body.tableCode).eq('active',true).maybeSingle();table=data;restaurant=data?.restaurants||null}else{const{data}=await supabase.from('restaurants').select('id').eq('slug',body.restaurantSlug).maybeSingle();restaurant=data||null;if(restaurant){const{data:t}=await supabase.from('restaurant_tables').select('id,active').eq('restaurant_id',restaurant.id).eq('public_token',body.tableToken).eq('active',true).maybeSingle();table=t}}if(!restaurant||!table)return res.status(404).json({error:'Invalid table QR'});const{data:active,error}=await supabase.from('customer_sessions').select('id,session_token').eq('restaurant_id',restaurant.id).eq('table_id',table.id).gt('expires_at',new Date().toISOString()).order('created_at',{ascending:false}).limit(1);if(error)throw error;const session=active?.[0];if(!session)return res.status(409).json({error:'Table is available now. Scan the QR again.',code:'TABLE_AVAILABLE'});if(sessionJoinCode(session.session_token)!==body.joinCode.toUpperCase())return res.status(401).json({error:'Invalid join code',code:'INVALID_JOIN_CODE'});setSessionCookie(res,session.session_token);res.json({ok:true,joined:true,join_code:sessionJoinCode(session.session_token)})}catch(e){console.error(e);res.status(400).json({error:'Unable to join table session'})}});
async function adminAuth(req, res, next) {
  try {
    const token = req.cookies?.admin_session;
    if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data, error } = await supabase
      .from('restaurant_members')
      .select('restaurant_id,role,users!inner(id,email),restaurants!inner(name,status)').eq('restaurants.status','active')
      .eq('user_id', decoded.sub)
      .limit(1)
      .maybeSingle();
    if (error || !data || !['owner','manager','kitchen','staff'].includes(data.role))
      return res.status(403).json({ error: 'Forbidden' });
    req.admin = {
      user_id: decoded.sub, restaurant_id: data.restaurant_id,
      role: data.role, restaurant_name: data.restaurants.name
    };
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

app.get('/api/admin/restaurant', adminAuth, async (req,res)=>{
  try{
    const {data,error}=await supabase.from('restaurants').select('id,name,slug,created_at').eq('id',req.admin.restaurant_id).maybeSingle();
    if(error)throw error;if(!data)return res.status(404).json({error:'Restaurant not found'});res.json({restaurant:data});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to load restaurant settings'})}
});
app.get('/api/admin/setup', adminAuth, async (req,res)=>{
  try{
    const {data,error}=await supabase.from('restaurants').select('id,name,slug,status,plan,onboarding_completed,logo_url,cover_image_url,phone,address,google_maps_url,instagram_url,facebook_url,default_language').eq('id',req.admin.restaurant_id).maybeSingle();
    if(error)throw error;if(!data)return res.status(404).json({error:'Restaurant not found'});res.json({restaurant:data});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to load setup'})}
});

app.patch('/api/admin/restaurant', adminAuth, async (req,res)=>{
  if(req.admin.role!=='owner')return res.status(403).json({error:'Only the owner can change restaurant settings'});
  try{
    const body=z.object({
      name:z.string().min(2).max(120).optional(),
      logo_url:z.string().url().max(1000).nullable().optional(),
      cover_image_url:z.string().url().max(1000).nullable().optional(),
      phone:z.string().max(30).nullable().optional(),
      address:z.string().max(300).nullable().optional(),
      google_maps_url:z.string().url().max(1000).nullable().optional(),
      instagram_url:z.string().url().max(1000).nullable().optional(),
      facebook_url:z.string().url().max(1000).nullable().optional(),
      default_language:z.enum(['en','kn','bilingual']).optional(),
      onboarding_completed:z.boolean().optional()
    }).parse(req.body);
    const update={...body};if(update.name)update.name=update.name.trim();
    const {data,error}=await supabase.from('restaurants').update(update).eq('id',req.admin.restaurant_id).select('id,name,slug,status,plan,onboarding_completed,logo_url,cover_image_url,phone,address,google_maps_url,instagram_url,facebook_url,default_language').single();
    if(error)throw error;res.json({restaurant:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to update restaurant settings'})}
});
app.get('/api/admin/staff', adminAuth, async (req,res)=>{
  try{
    const {data,error}=await supabase.from('restaurant_members')
      .select('user_id,role,users!inner(id,email)')
      .eq('restaurant_id',req.admin.restaurant_id)
      .order('role').order('user_id');
    if(error)throw error;
    res.json({staff:(data||[]).map(m=>({user_id:m.user_id,email:m.users.email,role:m.role,is_current:m.user_id===req.admin.user_id}))});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to load staff'})}
});
app.get('/api/admin/menu', adminAuth, async (req,res)=>{
  try{
    const {data,error}=await supabase.from('menu_items').select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order').eq('restaurant_id',req.admin.restaurant_id).order('category').order('sort_order');
    if(error)throw error;
    res.json({items:data||[]});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to load menu'})}
});
function canManageMenu(req,res){
  if(!['owner','manager'].includes(req.admin.role)){res.status(403).json({error:'Only owners and managers can manage the menu'});return false}
  return true
}
app.post('/api/admin/menu/bulk', adminAuth, async (req,res)=>{
  if(!canManageMenu(req,res))return;
  try{
    const body=z.object({items:z.array(z.object({
      name_en:z.string().min(1).max(150),
      name_kn:z.string().max(150).optional().default(''),
      description_en:z.string().max(500).optional().default(''),
      description_kn:z.string().max(500).optional().default(''),
      price:z.coerce.number().nonnegative(),
      price_large:z.union([z.coerce.number().nonnegative(),z.null()]).optional().default(null),
      image_url:z.string().url().max(1000).optional().or(z.literal('')).default(''),
      category:z.string().min(1).max(100),
      is_available:z.boolean().default(true),
      sort_order:z.coerce.number().int().default(0)
    })).min(1).max(500)}).parse(req.body);
    const rows=body.items.map(x=>({...x,restaurant_id:req.admin.restaurant_id}));
    const{data,error}=await supabase.from('menu_items').insert(rows).select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order');
    if(error)throw error;
    res.status(201).json({inserted:(data||[]).length,items:data||[]});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to import menu items'})}
});

app.post('/api/admin/menu', adminAuth, async (req,res)=>{
  if(!canManageMenu(req,res))return;
  try{
    const body=z.object({name_en:z.string().min(1).max(150),name_kn:z.string().max(150).optional().default(''),description_en:z.string().max(500).optional().default(''),description_kn:z.string().max(500).optional().default(''),price:z.coerce.number().nonnegative(),price_large:z.union([z.coerce.number().nonnegative(),z.null()]).optional().default(null),image_url:z.string().url().max(1000).optional().or(z.literal('')).default(''),category:z.string().min(1).max(100),is_available:z.boolean().default(true),sort_order:z.coerce.number().int().default(0)}).parse(req.body);
    const {data,error}=await supabase.from('menu_items').insert({...body,restaurant_id:req.admin.restaurant_id}).select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order').single();
    if(error)throw error; res.status(201).json({item:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to create menu item'})}
});
app.patch('/api/admin/menu/:id', adminAuth, async (req,res)=>{
  if(!canManageMenu(req,res))return;
  try{
    const body=z.object({name_en:z.string().min(1).max(150).optional(),name_kn:z.string().max(150).optional(),description_en:z.string().max(500).optional(),description_kn:z.string().max(500).optional(),price:z.coerce.number().nonnegative().optional(),price_large:z.union([z.coerce.number().nonnegative(),z.null()]).optional(),image_url:z.string().url().max(1000).optional().or(z.literal('')),category:z.string().min(1).max(100).optional(),is_available:z.boolean().optional(),sort_order:z.coerce.number().int().optional()}).parse(req.body);
    const {data,error}=await supabase.from('menu_items').update(body).eq('id',req.params.id).eq('restaurant_id',req.admin.restaurant_id).select('id,name_en,name_kn,description_en,description_kn,price,price_large,image_url,category,is_available,sort_order').maybeSingle();
    if(error)throw error;if(!data)return res.status(404).json({error:'Menu item not found'});res.json({item:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to update menu item'})}
});
app.delete('/api/admin/menu/:id', adminAuth, async (req,res)=>{
  if(!canManageMenu(req,res))return;
  try{
    const {error}=await supabase.from('menu_items').delete().eq('id',req.params.id).eq('restaurant_id',req.admin.restaurant_id);
    if(error)throw error;res.json({ok:true});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to delete menu item'})}
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const body = z.object({
      email: z.string().email().max(200),
      password: z.string().min(8).max(200)
    }).parse(req.body);
    if (!JWT_SECRET) return res.status(503).json({ error: 'Admin authentication is not configured' });

    const { data: user, error } = await supabase
      .from('users').select('id,password_hash').ilike('email', body.email).maybeSingle();
    if (error || !user || !(await bcrypt.compare(body.password, user.password_hash)))
      return res.status(401).json({ error: 'Invalid credentials' });

    const { data: member } = await supabase
      .from('restaurant_members').select('restaurant_id,role').eq('user_id', user.id).limit(1).maybeSingle();
    if (!member) return res.status(403).json({ error: 'No restaurant access' });

    const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '12h' });
    res.cookie('admin_session', token, {
      httpOnly: true, secure: true,
      sameSite: 'none', path: '/', maxAge: 12 * 60 * 60 * 1000
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Invalid login request' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_session', { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
  res.json({ ok: true });
});

app.patch('/api/admin/orders/:id/payment', adminAuth, async (req,res) => {
  if(!['owner','manager','kitchen'].includes(req.admin.role)) return res.status(403).json({error:'Only management or kitchen can mark payments complete'});
  try {
    const body = z.object({ payment_method: z.enum(['cash','upi','card','other']) }).parse(req.body);
    const { data, error } = await supabase.from('orders')
      .update({payment_status:'paid',payment_method:body.payment_method,paid_at:new Date().toISOString()})
      .eq('id',req.params.id).eq('restaurant_id',req.admin.restaurant_id).eq('payment_status','unpaid')
      .select('id,payment_status,payment_method,paid_at').maybeSingle();
    if(error) throw error;
    if(!data) return res.status(404).json({error:'Order not found or already paid'});
    res.json(data);
  } catch(e) { console.error(e); res.status(400).json({error:'Could not mark order as paid'}); }
});

app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('id,status,total,created_at,payment_status,payment_method,paid_at,restaurant_tables!inner(label),order_items(id,name_snapshot,quantity,price_snapshot,variant_snapshot)')
      .eq('restaurant_id', req.admin.restaurant_id)
      .neq('status', 'served')
      .neq('status', 'cancelled')
      .order('created_at', { ascending: false });
    if (error) throw error;
    const orders = (data || []).map(o => ({
      id: o.id, status: o.status, total: o.total, created_at: o.created_at, payment_status: o.payment_status, payment_method: o.payment_method, paid_at: o.paid_at,
      table_label: o.restaurant_tables.label,
      items: (o.order_items || []).map(i => ({ name: i.name_snapshot, quantity: i.quantity, price: i.price_snapshot, variant: i.variant_snapshot }))
    }));
    res.json({ restaurant_name: req.admin.restaurant_name, role: req.admin.role, orders });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Unable to load orders' });
  }
});

app.get('/api/admin/kitchen/history', adminAuth, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
    const { data, error } = await supabase
      .from('orders')
      .select('id,status,total,created_at,payment_status,payment_method,paid_at,restaurant_tables!inner(label),order_items(id,name_snapshot,quantity,price_snapshot,variant_snapshot)')
      .eq('restaurant_id', req.admin.restaurant_id)
      .in('status', ['served','cancelled'])
      .order('created_at', { ascending: false })
      .limit(limit);
    if (error) throw error;
    const orders = (data || []).map(o => ({
      id:o.id,status:o.status,total:o.total,created_at:o.created_at,
      payment_status:o.payment_status,payment_method:o.payment_method,paid_at:o.paid_at,
      table_label:o.restaurant_tables.label,
      items:(o.order_items||[]).map(i=>({name:i.name_snapshot,quantity:i.quantity,price:i.price_snapshot,variant:i.variant_snapshot}))
    }));
    res.json({restaurant_name:req.admin.restaurant_name,orders});
  } catch (e) {
    console.error(e);
    res.status(500).json({error:'Unable to load kitchen history'});
  }
});

app.patch('/api/admin/orders/:id', adminAuth, async (req, res) => {
  try {
    const body = z.object({
      status: z.enum(['received','accepted','preparing','ready','served','cancelled'])
    }).parse(req.body);
    const { data, error } = await supabase
      .from('orders').update({ status: body.status })
      .eq('id', req.params.id).eq('restaurant_id', req.admin.restaurant_id)
      .select('id,status').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Order not found' });
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Invalid order update' });
  }
});

app.post('/api/admin/tables', adminAuth, async (req,res)=>{
  if(!['owner','manager'].includes(req.admin.role))return res.status(403).json({error:'Only owners and managers can manage tables'});
  try{
    const body=z.object({label:z.string().min(1).max(50)}).parse(req.body);
    const token='mudcups-table-'+Date.now().toString(36)+'-'+crypto.randomBytes(8).toString('hex'); const shortCode=crypto.randomBytes(5).toString('base64url').slice(0,8);
    const {data,error}=await supabase.from('restaurant_tables').insert({restaurant_id:req.admin.restaurant_id,label:body.label.trim(),public_token:token,short_code:shortCode,active:true}).select('id,label,active,public_token,short_code').single();
    if(error)throw error;res.status(201).json({table:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to create table'})}
});
app.patch('/api/admin/tables/:id', adminAuth, async (req,res)=>{
  if(!['owner','manager'].includes(req.admin.role))return res.status(403).json({error:'Only owners and managers can manage tables'});
  try{
    const body=z.object({label:z.string().min(1).max(50).optional(),active:z.boolean().optional()}).parse(req.body);
    const {data,error}=await supabase.from('restaurant_tables').update(body).eq('id',req.params.id).eq('restaurant_id',req.admin.restaurant_id).select('id,label,active,public_token').maybeSingle();
    if(error)throw error;if(!data)return res.status(404).json({error:'Table not found'});res.json({table:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to update table'})}
});
app.get('/api/admin/tables', adminAuth, async (req, res) => {
  try {
    const [{ data: tables, error: tableError }, { data: sessions, error: sessionError }, { data: orders, error: orderError }, { data: requests, error: requestError }] = await Promise.all([
      supabase.from('restaurant_tables').select('id,label,active,public_token,short_code').eq('restaurant_id', req.admin.restaurant_id).order('label'),
      supabase.from('customer_sessions').select('id,table_id,created_at,expires_at').eq('restaurant_id', req.admin.restaurant_id).gt('expires_at', new Date().toISOString()).order('created_at',{ascending:false}),
      supabase.from('orders').select('id,table_id,status,total,created_at,payment_status,payment_method,paid_at').eq('restaurant_id', req.admin.restaurant_id).not('status','in','(served,cancelled)').order('created_at',{ascending:false}),
      supabase.from('service_requests').select('table_id,type,status').eq('restaurant_id', req.admin.restaurant_id).in('status',['pending','acknowledged'])
    ]);
    if (tableError) throw tableError;
    if (sessionError) throw sessionError;
    if (orderError) throw orderError;
    if (requestError) throw requestError;
    const latestSession = new Map();
    for (const s of (sessions || [])) if (!latestSession.has(s.table_id)) latestSession.set(s.table_id,s);
    const latestOrder = new Map();
    for (const o of (orders || [])) if (!latestOrder.has(o.table_id)) latestOrder.set(o.table_id,o);
    const requestCounts = new Map();
    for (const r of (requests || [])) requestCounts.set(r.table_id,(requestCounts.get(r.table_id)||0)+1);
    res.json({ tables:(tables||[]).map(t=>{
      const session = latestSession.get(t.id);
      const order = latestOrder.get(t.id)||null;
      return {
        id:t.id,label:t.label,active:t.active,public_token:t.public_token,short_code:t.short_code,
        occupied:!!session,
        session_id:session?.id||null,
        session_started_at:session?.created_at||null,
        order,
        requests:requestCounts.get(t.id)||0
      };
    })});
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'Unable to load table status' });
  }
});

app.post('/api/admin/tables/:id/close-session', adminAuth, async (req,res) => {
  if(!['owner','manager','kitchen'].includes(req.admin.role)) return res.status(403).json({error:'Only management or kitchen can close table sessions'});
  try {
    const now = new Date().toISOString();
    const ref = req.params.id;

    // The dashboard may send either the physical table id or the active
    // customer session id. Resolve both forms safely within this restaurant.
    let session = null;
    let sessionError = null;

    const bySession = await supabase
      .from('customer_sessions')
      .select('id,table_id,expires_at')
      .eq('id', ref)
      .eq('restaurant_id', req.admin.restaurant_id)
      .gt('expires_at', now)
      .maybeSingle();

    if (bySession.error) {
      sessionError = bySession.error;
    } else if (bySession.data) {
      session = bySession.data;
    } else {
      const byTable = await supabase
        .from('customer_sessions')
        .select('id,table_id,expires_at')
        .eq('table_id', ref)
        .eq('restaurant_id', req.admin.restaurant_id)
        .gt('expires_at', now)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      sessionError = byTable.error;
      session = byTable.data || null;
    }

    if (sessionError) throw sessionError;
    if (!session) return res.status(404).json({error:'No active customer session for this table'});

    const { data: unpaidOrders, error: unpaidError } = await supabase
      .from('orders')
      .select('id,total,status')
      .eq('session_id', session.id)
      .neq('status', 'cancelled')
      .eq('payment_status', 'unpaid');

    if (unpaidError) throw unpaidError;

    if (unpaidOrders?.length) {
      return res.status(409).json({
        error:'Please settle all orders before closing the table',
        code:'UNPAID_ORDERS',
        unpaid_count:unpaidOrders.length,
        unpaid_total:unpaidOrders.reduce((sum,o)=>sum+Number(o.total||0),0)
      });
    }

    const { data: closedSession, error: closeError } = await supabase
      .from('customer_sessions')
      .update({expires_at:now})
      .eq('id',session.id)
      .eq('restaurant_id',req.admin.restaurant_id)
      .select('id,table_id,expires_at')
      .maybeSingle();

    if (closeError) throw closeError;
    if (!closedSession) return res.status(404).json({error:'Session was already closed'});

    const { error: requestError } = await supabase
      .from('service_requests')
      .update({status:'completed'})
      .eq('session_id',session.id)
      .eq('restaurant_id',req.admin.restaurant_id)
      .in('status',['pending','acknowledged']);

    if (requestError) throw requestError;

    res.json({ok:true,table_id:session.table_id,session_id:session.id,table_closed:true});
  } catch(e) {
    console.error(e);
    res.status(400).json({error:e?.message||'Could not close table session'});
  }
});

app.post('/api/admin/tables/:id/mark-paid', adminAuth, async (req,res) => {
  if(!['owner','manager','kitchen'].includes(req.admin.role)) return res.status(403).json({error:'Only management or kitchen can mark payments complete'});
  try{
    const now=new Date().toISOString(), ref=req.params.id;
    let session=null, sessionError=null;
    const bySession=await supabase.from('customer_sessions').select('id,table_id,expires_at').eq('id',ref).eq('restaurant_id',req.admin.restaurant_id).gt('expires_at',now).maybeSingle();
    if(bySession.error) sessionError=bySession.error;
    else if(bySession.data) session=bySession.data;
    else {
      const byTable=await supabase.from('customer_sessions').select('id,table_id,expires_at').eq('table_id',ref).eq('restaurant_id',req.admin.restaurant_id).gt('expires_at',now).order('created_at',{ascending:false}).limit(1).maybeSingle();
      sessionError=byTable.error; session=byTable.data||null;
    }
    if(sessionError) throw sessionError;
    if(!session) return res.status(404).json({error:'No active customer session for this table'});
    const {data,error}=await supabase.from('orders')
      .update({payment_status:'paid',payment_method:'cash',paid_at:now})
      .eq('session_id',session.id).eq('restaurant_id',req.admin.restaurant_id)
      .neq('status','cancelled').eq('payment_status','unpaid').select('id,total');
    if(error) throw error;
    const paidOrders=data||[];
    if(!paidOrders.length) return res.status(409).json({error:'There are no unpaid orders for this table'});
    res.json({ok:true,table_id:session.table_id,session_id:session.id,paid_orders:paidOrders.length,paid_total:paidOrders.reduce((sum,o)=>sum+Number(o.total||0),0),payment_method:'cash'});
  }catch(e){console.error(e);res.status(400).json({error:e?.message||'Could not mark table payment complete'})}
});

app.get('/api/admin/bills/history', adminAuth, async (req,res) => {
  try {
    const [{data:orders,error:ordersError},{data:payments,error:paymentsError}] = await Promise.all([
      supabase.from('orders')
        .select('id,session_id,table_id,total,status,created_at,payment_status,payment_method,paid_at,restaurant_tables!inner(label),customer_sessions!inner(customer_name,created_at)')
        .eq('restaurant_id',req.admin.restaurant_id)
        .eq('payment_status','paid')
        .neq('status','cancelled')
        .order('paid_at',{ascending:false})
        .limit(1000),
      supabase.from('bill_payments')
        .select('id,session_id,amount,currency,provider,provider_order_id,provider_payment_id,status,created_at,paid_at')
        .eq('restaurant_id',req.admin.restaurant_id)
        .eq('status','paid')
        .order('paid_at',{ascending:false})
        .limit(1000)
    ]);
    if(ordersError) throw ordersError;
    if(paymentsError) throw paymentsError;

    const paymentBySession=new Map();
    for(const payment of (payments||[])){
      if(!paymentBySession.has(payment.session_id)) paymentBySession.set(payment.session_id,payment);
    }

    const grouped=new Map();
    for(const order of (orders||[])){
      if(!order.session_id) continue;
      let bill=grouped.get(order.session_id);
      if(!bill){
        const payment=paymentBySession.get(order.session_id);
        bill={
          id:order.session_id,
          table_label:order.restaurant_tables?.label||'Table',
          customer_name:order.customer_sessions?.customer_name||'Guest',
          amount:0,
          order_count:0,
          order_ids:[],
          created_at:order.customer_sessions?.created_at||order.created_at,
          paid_at:order.paid_at||payment?.paid_at||order.created_at,
          payment_method:payment?.provider==='razorpay'?'upi':(order.payment_method||'other'),
          provider:payment?.provider||null,
          transaction_id:payment?.provider_payment_id||null,
          provider_order_id:payment?.provider_order_id||null
        };
        grouped.set(order.session_id,bill);
      }
      bill.amount+=Number(order.total||0);
      bill.order_count+=1;
      bill.order_ids.push(order.id);
      if(new Date(order.paid_at||0)>new Date(bill.paid_at||0)) bill.paid_at=order.paid_at;
      if(!bill.transaction_id){
        const payment=paymentBySession.get(order.session_id);
        if(payment){
          bill.provider=payment.provider||bill.provider;
          bill.transaction_id=payment.provider_payment_id||null;
          bill.provider_order_id=payment.provider_order_id||null;
          bill.payment_method=payment.provider==='razorpay'?'upi':bill.payment_method;
          bill.paid_at=payment.paid_at||bill.paid_at;
        }
      }
    }

    const bills=Array.from(grouped.values()).sort((a,b)=>new Date(b.paid_at)-new Date(a.paid_at));
    res.json({restaurant_name:req.admin.restaurant_name,bills});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:'Unable to load bill history'});
  }
});

app.get('/api/admin/service-requests', adminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('service_requests')
      .select('id,type,status,created_at,restaurant_tables!inner(label)')
      .eq('restaurant_id', req.admin.restaurant_id)
      .in('status', ['pending','acknowledged'])
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    const requests = (data || []).map(r => ({
      id: r.id, type: r.type, status: r.status, created_at: r.created_at,
      table_label: r.restaurant_tables.label
    }));
    res.json({ requests });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Unable to load service requests' });
  }
});

app.patch('/api/admin/service-requests/:id', adminAuth, async (req, res) => {
  try {
    const body = z.object({
      status: z.enum(['pending','acknowledged','completed','cancelled'])
    }).parse(req.body);
    const { data, error } = await supabase
      .from('service_requests')
      .update({ status: body.status })
      .eq('id', req.params.id)
      .eq('restaurant_id', req.admin.restaurant_id)
      .select('id,type,status,created_at')
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Service request not found' });
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Invalid service request update' });
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const { data, error } = await supabase
      .from('orders')
      .select('id,status,total,created_at,order_items(id,name_snapshot,quantity,price_snapshot,variant_snapshot)')
      .eq('session_id', session.session_id)
      .eq('restaurant_id', session.restaurant_id)
      .order('created_at', { ascending: false })
      .limit(20);
    if (error) throw error;
    const orders = (data || []).map(o => ({
      id:o.id,status:o.status,total:o.total,created_at:o.created_at,
      items:(o.order_items||[]).map(i=>({
        name:i.name_snapshot,quantity:i.quantity,price:i.price_snapshot,variant:i.variant_snapshot
      }))
    }));
    res.json({ table_label:session.table_label, orders });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'Unable to load order history' });
  }
});

async function razorpayRequest(path, options = {}) {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) throw new Error('Razorpay is not configured');
  const auth = Buffer.from(process.env.RAZORPAY_KEY_ID + ':' + process.env.RAZORPAY_KEY_SECRET).toString('base64');
  const response = await fetch('https://api.razorpay.com/v1' + path, {
    ...options,
    headers: {
      Authorization: 'Basic ' + auth,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.error?.description || 'Razorpay request failed');
    error.status = response.status;
    throw error;
  }
  return data;
}

function verifyHmac(payload, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(signature || '')));
}

app.get('/api/bill', async (req,res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({error:'Table session expired'});
    const { data, error } = await supabase
      .from('orders')
      .select('id,status,total,created_at,payment_status,payment_method,paid_at,order_items(id,name_snapshot,quantity,price_snapshot,variant_snapshot)')
      .eq('session_id',session.session_id)
      .eq('restaurant_id',session.restaurant_id)
      .neq('status','cancelled')
      .order('created_at',{ascending:true});
    if(error) throw error;
    const orders=(data||[]).map(o=>({
      id:o.id,status:o.status,total:Number(o.total),created_at:o.created_at,
      payment_status:o.payment_status||'unpaid',payment_method:o.payment_method||null,paid_at:o.paid_at||null,
      items:(o.order_items||[]).map(i=>({name:i.name_snapshot,quantity:i.quantity,price:Number(i.price_snapshot),variant:i.variant_snapshot}))
    }));
    const grandTotal=orders.reduce((sum,o)=>sum+o.total,0);
    const unpaidTotal=orders.filter(o=>o.payment_status!=='paid').reduce((sum,o)=>sum+o.total,0);
    res.json({
      restaurant_name:session.restaurant_name,table_label:session.table_label,orders,
      grand_total:grandTotal,unpaid_total:unpaidTotal,
      payment_mode:(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET && process.env.DEMO_PAYMENT_MODE !== 'true') ? 'live' : 'demo',
      payment_key_id:(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET && process.env.DEMO_PAYMENT_MODE !== 'true') ? process.env.RAZORPAY_KEY_ID : null,
      payment_vpa:process.env.RESTAURANT_UPI_VPA || 'demo@upi'
    });
  } catch(e) { console.error(e); res.status(500).json({error:'Unable to load bill'}); }
});

app.post('/api/bill/payment/order', async (req,res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({error:'Table session expired'});
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET || process.env.DEMO_PAYMENT_MODE === 'true') {
      return res.status(503).json({error:'Live payments are not configured'});
    }
    const { data: orders, error } = await supabase
      .from('orders')
      .select('id,total,payment_status,status')
      .eq('session_id',session.session_id)
      .eq('restaurant_id',session.restaurant_id)
      .neq('status','cancelled')
      .eq('payment_status','unpaid')
      .order('created_at',{ascending:true});
    if (error) throw error;
    if (!orders?.length) return res.status(400).json({error:'No unpaid orders'});
    const amount = orders.reduce((sum,o)=>sum+Number(o.total),0);
    const amountPaise = Math.round(amount * 100);
    const receipt = ('mt_' + session.session_id.replace(/-/g,'')).slice(0,40);
    const razorOrder = await razorpayRequest('/orders', {
      method:'POST',
      body:JSON.stringify({amount:amountPaise,currency:'INR',receipt,payment_capture:1})
    });
    const {data:payment,error:paymentError}=await supabase.from('bill_payments').insert({
      restaurant_id:session.restaurant_id,
      session_id:session.session_id,
      order_ids:orders.map(o=>o.id),
      amount,
      currency:'INR',
      provider:'razorpay',
      provider_order_id:razorOrder.id,
      status:'created'
    }).select('id').single();
    if(paymentError) throw paymentError;
    res.json({
      payment_id:payment.id,
      key_id:process.env.RAZORPAY_KEY_ID,
      order_id:razorOrder.id,
      amount:amountPaise,
      currency:'INR',
      name:session.restaurant_name,
      description:'Table bill · '+session.table_label
    });
  } catch(e) {
    console.error(e);
    res.status(400).json({error:'Could not start payment'});
  }
});

app.post('/api/bill/payment/verify', async (req,res) => {
  try {
    const session=await customerSession(req);
    if(!session) return res.status(401).json({error:'Table session expired'});
    const body=z.object({
      razorpay_order_id:z.string().min(1),
      razorpay_payment_id:z.string().min(1),
      razorpay_signature:z.string().min(1)
    }).parse(req.body);
    const {data:payment,error}=await supabase.from('bill_payments')
      .select('id,session_id,restaurant_id,order_ids,amount,status,provider_order_id')
      .eq('provider_order_id',body.razorpay_order_id)
      .eq('session_id',session.session_id)
      .eq('restaurant_id',session.restaurant_id)
      .maybeSingle();
    if(error) throw error;
    if(!payment) return res.status(404).json({error:'Payment session not found'});
    if(!verifyHmac(body.razorpay_order_id+'|'+body.razorpay_payment_id,body.razorpay_signature,process.env.RAZORPAY_KEY_SECRET)) {
      return res.status(400).json({error:'Payment signature verification failed'});
    }
    const razorPayment=await razorpayRequest('/payments/'+encodeURIComponent(body.razorpay_payment_id));
    const expectedPaise=Math.round(Number(payment.amount)*100);
    if(razorPayment.order_id!==payment.provider_order_id || Number(razorPayment.amount)!==expectedPaise || razorPayment.status!=='captured') {
      return res.status(400).json({error:'Payment is not captured for the expected amount'});
    }
    const now=new Date().toISOString();
    const {error:updatePaymentError}=await supabase.from('bill_payments')
      .update({provider_payment_id:body.razorpay_payment_id,status:'paid',paid_at:now})
      .eq('id',payment.id);
    if(updatePaymentError) throw updatePaymentError;
    const {error:updateOrdersError}=await supabase.from('orders')
      .update({payment_status:'paid',payment_method:'upi',paid_at:now})
      .in('id',payment.order_ids)
      .eq('session_id',session.session_id)
      .eq('restaurant_id',session.restaurant_id)
      .eq('payment_status','unpaid');
    if(updateOrdersError) throw updateOrdersError;
    await supabase.from('customer_sessions').update({expires_at:now}).eq('id',session.session_id).eq('restaurant_id',session.restaurant_id);await supabase.from('service_requests').update({status:'completed'}).eq('session_id',session.session_id).eq('restaurant_id',session.restaurant_id).in('status',['pending','acknowledged']);res.json({ok:true,payment_id:body.razorpay_payment_id,table_closed:true});
  } catch(e) {
    console.error(e);
    res.status(400).json({error:e instanceof z.ZodError?'Invalid payment response':(e.message||'Payment verification failed')});
  }
});

app.post('/api/webhooks/razorpay', async (req,res) => {
  try {
    if(!process.env.RAZORPAY_WEBHOOK_SECRET) return res.status(503).send('Webhook not configured');
    const signature=req.headers['x-razorpay-signature'];
    if(!verifyHmac(req.rawBody || JSON.stringify(req.body),signature,process.env.RAZORPAY_WEBHOOK_SECRET)) return res.status(400).send('Invalid signature');
    const event=req.body?.event;
    if(event==='payment.captured'){
      const entity=req.body?.payload?.payment?.entity;
      const providerOrderId=entity?.order_id;
      const providerPaymentId=entity?.id;
      if(providerOrderId && providerPaymentId){
        const {data:payment,error}=await supabase.from('bill_payments')
          .select('id,order_ids,amount,status,session_id,restaurant_id')
          .eq('provider_order_id',providerOrderId)
          .maybeSingle();
        if(error) throw error;
        if(payment && payment.status!=='paid' && Number(entity.amount)===Math.round(Number(payment.amount)*100)){
          const now=new Date().toISOString();
          await supabase.from('bill_payments').update({provider_payment_id:providerPaymentId,status:'paid',paid_at:now}).eq('id',payment.id);
          await supabase.from('orders').update({payment_status:'paid',payment_method:'upi',paid_at:now}).in('id',payment.order_ids).eq('payment_status','unpaid');
          const {data:remaining}=await supabase.from('orders').select('id').eq('session_id',payment.session_id).eq('restaurant_id',payment.restaurant_id).neq('status','cancelled').eq('payment_status','unpaid');
          if(!(remaining||[]).length) { await supabase.from('customer_sessions').update({expires_at:now}).eq('id',payment.session_id).eq('restaurant_id',payment.restaurant_id); await supabase.from('service_requests').update({status:'completed'}).eq('session_id',payment.session_id).eq('restaurant_id',payment.restaurant_id).in('status',['pending','acknowledged']); }
        }
      }
    }
    res.json({ok:true});
  } catch(e) {
    console.error(e);
    res.status(400).send('Webhook processing failed');
  }
});

app.post('/api/bill/demo-pay', async (req,res) => {
  try {
    if (process.env.DEMO_PAYMENT_MODE === 'false') return res.status(403).json({error:'Demo payments are disabled'});
    const session=await customerSession(req);
    if(!session) return res.status(401).json({error:'Table session expired'});
    const {data,error}=await supabase.from('orders')
      .update({payment_status:'paid',payment_method:'upi',paid_at:new Date().toISOString()})
      .eq('session_id',session.session_id).eq('restaurant_id',session.restaurant_id)
      .neq('status','cancelled').eq('payment_status','unpaid').select('id');
    if(error) throw error;
    await supabase.from('customer_sessions').update({expires_at:new Date().toISOString()}).eq('id',session.session_id).eq('restaurant_id',session.restaurant_id);await supabase.from('service_requests').update({status:'completed'}).eq('session_id',session.session_id).eq('restaurant_id',session.restaurant_id).in('status',['pending','acknowledged']);res.json({ok:true,paid_orders:(data||[]).length,table_closed:true});
  } catch(e) { console.error(e); res.status(400).json({error:'Demo payment could not be completed'}); }
});

app.post('/api/orders', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const body = orderSchema.parse(req.body);
    const rpcItems = body.items.map(i => ({ menu_item_id: i.menu_item_id, qty: i.quantity, size: i.size }));
    const { data, error } = await supabase.rpc('place_order', {
      p_restaurant_id: session.restaurant_id,
      p_table_id: session.table_id,
      p_session_id: session.session_id,
      p_items: rpcItems
    });
    if (error) {
      console.error(error);
      const msg = error.message?.includes('item_unavailable') ? 'One or more menu items are unavailable' :
        error.message?.includes('invalid_session') ? 'Table session expired' : 'Could not place order';
      return res.status(400).json({ error: msg });
    }
    res.status(201).json({ order: data, table_label: session.table_label });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: e instanceof z.ZodError ? 'Invalid order' : 'Could not place order' });
  }
});

app.get('/api/service-requests', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const { data, error } = await supabase
      .from('service_requests')
      .select('id,type,status,created_at')
      .eq('session_id', session.session_id)
      .eq('restaurant_id', session.restaurant_id)
      .in('status', ['pending','acknowledged'])
      .order('created_at', { ascending: false })
      .limit(20);
    if (error) throw error;
    const latestByType = new Map();
    for (const request of (data || [])) {
      if (!latestByType.has(request.type)) latestByType.set(request.type, request);
    }
    res.json({ requests: Array.from(latestByType.values()) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Unable to load service requests' });
  }
});

app.patch('/api/service-requests/:id', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const body = z.object({ status: z.literal('cancelled') }).parse(req.body);
    const { data, error } = await supabase
      .from('service_requests')
      .update({ status: body.status })
      .eq('id', req.params.id)
      .eq('session_id', session.session_id)
      .eq('restaurant_id', session.restaurant_id)
      .in('status', ['pending','acknowledged'])
      .select('id,type,status,created_at')
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Request not found or already completed' });
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Could not cancel request' });
  }
});

app.post('/api/service-requests', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const body = z.object({ type: z.enum(['waiter','bill']) }).parse(req.body);
    const { data: existing, error: existingError } = await supabase
      .from('service_requests')
      .select('id,type,status,created_at')
      .eq('session_id', session.session_id)
      .eq('restaurant_id', session.restaurant_id)
      .eq('type', body.type)
      .in('status', ['pending','acknowledged'])
      .order('created_at', { ascending: false })
      .limit(1);
    if (existingError) throw existingError;
    if (existing?.length) return res.status(200).json(existing[0]);

    const { data, error } = await supabase.from('service_requests').insert({
      restaurant_id: session.restaurant_id, table_id: session.table_id,
      session_id: session.session_id, type: body.type
    }).select('id,type,status,created_at').single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Could not create request' });
  }
});


// Platform SaaS control center
async function platformAuth(req,res,next){
  try{
    const token=req.cookies?.platform_session;
    if(!token||!JWT_SECRET)return res.status(401).json({error:'Unauthorized'});
    const decoded=jwt.verify(token,JWT_SECRET);
    const{data:user,error}=await supabase.from('users').select('id,email').eq('id',decoded.sub).maybeSingle();
    const platformEmail=(process.env.PLATFORM_ADMIN_EMAIL||'').trim().toLowerCase();
    if(error||!user||!platformEmail||user.email.toLowerCase()!==platformEmail)return res.status(403).json({error:'Platform access denied'});
    req.platform={user_id:user.id,email:user.email};
    next();
  }catch{return res.status(401).json({error:'Unauthorized'})}
}

app.post('/api/platform/login',async(req,res)=>{
  try{
    const body=z.object({email:z.string().email().max(200),password:z.string().min(8).max(200)}).parse(req.body);
    const platformEmail=(process.env.PLATFORM_ADMIN_EMAIL||'').trim().toLowerCase();
    if(!platformEmail||body.email.toLowerCase()!==platformEmail)return res.status(403).json({error:'Platform access denied'});
    const{data:user,error}=await supabase.from('users').select('id,email,password_hash').ilike('email',body.email).maybeSingle();
    if(error||!user||!(await bcrypt.compare(body.password,user.password_hash)))return res.status(401).json({error:'Invalid credentials'});
    const token=jwt.sign({sub:user.id,platform:true},JWT_SECRET,{expiresIn:'12h'});
    res.cookie('platform_session',token,{httpOnly:true,secure:true,sameSite:'none',path:'/',maxAge:12*60*60*1000});
    res.json({ok:true});
  }catch(e){console.error(e);res.status(400).json({error:'Invalid platform login request'})}
});
app.post('/api/platform/logout',(req,res)=>{
  res.clearCookie('platform_session',{httpOnly:true,secure:true,sameSite:'none',path:'/'});
  res.json({ok:true});
});
app.get('/api/platform/me',platformAuth,(req,res)=>res.json({admin:req.platform}));

app.get('/api/platform/restaurants',platformAuth,async(req,res)=>{
  try{
    const{data:restaurants,error}=await supabase.from('restaurants').select('id,name,slug,status,plan,onboarding_completed,created_at').order('created_at',{ascending:false});
    if(error)throw error;
    const ids=(restaurants||[]).map(r=>r.id);
    const [{data:tables},{data:orders}]=await Promise.all([
      ids.length?supabase.from('restaurant_tables').select('restaurant_id').in('restaurant_id',ids):Promise.resolve({data:[]}),
      ids.length?supabase.from('orders').select('restaurant_id').in('restaurant_id',ids):Promise.resolve({data:[]})
    ]);
    const tc={},oc={};
    for(const x of tables||[])tc[x.restaurant_id]=(tc[x.restaurant_id]||0)+1;
    for(const x of orders||[])oc[x.restaurant_id]=(oc[x.restaurant_id]||0)+1;
    res.json({restaurants:(restaurants||[]).map(r=>({...r,table_count:tc[r.id]||0,order_count:oc[r.id]||0}))});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to load restaurants'})}
});

app.post('/api/platform/restaurants',platformAuth,async(req,res)=>{
  try{
    const body=z.object({
      name:z.string().min(2).max(120),
      slug:z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(80),
      ownerEmail:z.string().email().max(200),
      ownerName:z.string().max(120).optional().default(''),
      ownerPassword:z.string().min(8).max(200)
    }).parse(req.body);
    const slug=body.slug.toLowerCase().trim(),email=body.ownerEmail.toLowerCase().trim();
    const{data:slugExists}=await supabase.from('restaurants').select('id').eq('slug',slug).maybeSingle();
    if(slugExists)return res.status(409).json({error:'Restaurant slug already exists'});
    const{data:emailExists}=await supabase.from('users').select('id').ilike('email',email).maybeSingle();
    if(emailExists)return res.status(409).json({error:'Owner email already exists'});
    const{data:restaurant,error:restaurantError}=await supabase.from('restaurants').insert({name:body.name.trim(),slug,status:'active',plan:'starter',onboarding_completed:false}).select('id,name,slug,status,plan,onboarding_completed,created_at').single();
    if(restaurantError)throw restaurantError;
    const hash=await bcrypt.hash(body.ownerPassword,12);
    const{data:user,error:userError}=await supabase.from('users').insert({email,password_hash:hash}).select('id,email').single();
    if(userError){
      await supabase.from('restaurants').delete().eq('id',restaurant.id);
      throw userError;
    }
    const{error:memberError}=await supabase.from('restaurant_members').insert({user_id:user.id,restaurant_id:restaurant.id,role:'owner'});
    if(memberError){
      await supabase.from('users').delete().eq('id',user.id);
      await supabase.from('restaurants').delete().eq('id',restaurant.id);
      throw memberError;
    }
    res.status(201).json({restaurant,owner:{email:user.email,name:body.ownerName||null}});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to create restaurant'})}
});

app.patch('/api/platform/restaurants/:id',platformAuth,async(req,res)=>{
  try{
    const body=z.object({status:z.enum(['active','suspended','trial']).optional(),plan:z.enum(['starter','professional','business']).optional(),onboarding_completed:z.boolean().optional()}).parse(req.body);
    const{data,error}=await supabase.from('restaurants').update(body).eq('id',req.params.id).select('id,name,slug,status,plan,onboarding_completed,created_at').maybeSingle();
    if(error)throw error;if(!data)return res.status(404).json({error:'Restaurant not found'});res.json({restaurant:data});
  }catch(e){console.error(e);res.status(400).json({error:'Unable to update restaurant'})}
});

app.listen(process.env.PORT || 10000, () => console.log('API running on Supabase'));
