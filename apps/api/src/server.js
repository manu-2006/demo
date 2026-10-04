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

app.patch('/api/admin/orders/:id/payment', adminAuth, async (req,res) => {
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

app.get('/api/admin/tables', adminAuth, async (req, res) => {
  try {
    const [{ data: tables, error: tableError }, { data: sessions, error: sessionError }, { data: orders, error: orderError }, { data: requests, error: requestError }] = await Promise.all([
      supabase.from('restaurant_tables').select('id,label,active').eq('restaurant_id', req.admin.restaurant_id).order('label'),
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
        id:t.id,label:t.label,active:t.active,
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
  try {
    const now = new Date().toISOString();
    const { data: session, error: sessionError } = await supabase
      .from('customer_sessions')
      .select('id')
      .eq('id',req.params.id)
      .eq('restaurant_id',req.admin.restaurant_id)
      .maybeSingle();
    if (sessionError) throw sessionError;
    if (!session) return res.status(404).json({error:'Table session not found'});
    const { data: unpaidOrders, error: unpaidError } = await supabase
      .from('orders').select('id').eq('session_id',session.id).neq('status','cancelled').eq('payment_status','unpaid');
    if(unpaidError) throw unpaidError;
    if(unpaidOrders?.length) return res.status(409).json({error:'Please settle all orders before closing the table'});
    
    const { error: closeError } = await supabase
      .from('customer_sessions')
      .update({expires_at:now})
      .eq('id',session.id)
      .eq('restaurant_id',req.admin.restaurant_id);
    if (closeError) throw closeError;
    await supabase
      .from('service_requests')
      .update({status:'completed'})
      .eq('session_id',session.id)
      .eq('restaurant_id',req.admin.restaurant_id)
      .in('status',['pending','acknowledged']);
    res.json({ok:true});
  } catch(e) {
    console.error(e);
    res.status(400).json({error:'Could not close table session'});
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
    res.json({ok:true,payment_id:body.razorpay_payment_id});
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
          .select('id,order_ids,amount,status')
          .eq('provider_order_id',providerOrderId)
          .maybeSingle();
        if(error) throw error;
        if(payment && payment.status!=='paid' && Number(entity.amount)===Math.round(Number(payment.amount)*100)){
          const now=new Date().toISOString();
          await supabase.from('bill_payments').update({provider_payment_id:providerPaymentId,status:'paid',paid_at:now}).eq('id',payment.id);
          await supabase.from('orders').update({payment_status:'paid',payment_method:'upi',paid_at:now}).in('id',payment.order_ids).eq('payment_status','unpaid');
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
    res.json({ok:true,paid_orders:(data||[]).length});
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

app.listen(process.env.PORT || 10000, () => console.log('API running on Supabase'));
