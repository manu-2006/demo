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
app.use(cors({
  origin: process.env.WEB_ORIGIN || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
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

app.post('/api/session', async (req, res) => {
  try {
    const body = z.object({
      restaurantSlug: z.string().min(1).max(100),
      tableToken: z.string().min(20).max(100)
    }).parse(req.body);

    const { data: restaurant } = await supabase
      .from('restaurants').select('id').eq('slug', body.restaurantSlug).maybeSingle();
    if (!restaurant) return res.status(404).json({ error: 'Invalid restaurant' });

    const { data: table } = await supabase
      .from('restaurant_tables').select('id,active')
      .eq('restaurant_id', restaurant.id).eq('public_token', body.tableToken).eq('active', true).maybeSingle();
    if (!table) return res.status(404).json({ error: 'Invalid table QR' });

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
    const { error } = await supabase.from('customer_sessions').insert({
      restaurant_id: restaurant.id, table_id: table.id, session_token: token, expires_at: expires
    });
    if (error) throw error;
    setSessionCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Unable to start table session' });
  }
});

async function adminAuth(req, res, next) {
  try {
    const token = req.cookies?.admin_session;
    if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data, error } = await supabase
      .from('restaurant_members')
      .select('restaurant_id,role,users!inner(id,email),restaurants!inner(name)')
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

app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('id,status,total,created_at,restaurant_tables!inner(label),order_items(id,name_snapshot,quantity,price_snapshot,variant_snapshot)')
      .eq('restaurant_id', req.admin.restaurant_id)
      .neq('status', 'served')
      .order('created_at', { ascending: false });
    if (error) throw error;
    const orders = (data || []).map(o => ({
      id: o.id, status: o.status, total: o.total, created_at: o.created_at,
      table_label: o.restaurant_tables.label,
      items: (o.order_items || []).map(i => ({ name: i.name_snapshot, quantity: i.quantity, price: i.price_snapshot, variant: i.variant_snapshot }))
    }));
    res.json({ restaurant_name: req.admin.restaurant_name, role: req.admin.role, orders });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Unable to load orders' });
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

app.post('/api/service-requests', async (req, res) => {
  try {
    const session = await customerSession(req);
    if (!session) return res.status(401).json({ error: 'Table session expired' });
    const body = z.object({ type: z.enum(['waiter','bill']) }).parse(req.body);
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

app.listen(process.env.PORT || 10000, () => console.log('API running on Supabase'));
