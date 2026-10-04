import React,{useEffect,useState} from 'react';
import './platform.css';

const API='https://qr-restaurant-os-api.onrender.com';

async function api(path,options={}){
  const r=await fetch(API+path,{credentials:'include',headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error||'Request failed');
  return data;
}

function Confirm({data,onClose,onConfirm}){
  if(!data)return null;
  return <div className="premiumConfirmBackdrop" onClick={onClose}>
    <div className="premiumConfirm" onClick={e=>e.stopPropagation()}>
      <div className={'confirmIcon '+(data.danger?'danger':'')}><span>{data.danger?'!':'?'}</span></div>
      <div className="confirmCopy"><span className="confirmEyebrow">CONFIRM ACTION</span><h3>{data.title}</h3><p>{data.text}</p></div>
      <div className="confirmActions"><button className="confirmCancel" onClick={onClose}>Cancel</button><button className={data.danger?'confirmDanger':'confirmPrimary'} onClick={onConfirm}>{data.action||'Confirm'}</button></div>
    </div>
  </div>;
}

export default function Platform(){
  const[me,setMe]=useState(null),[restaurants,setRestaurants]=useState([]),[loading,setLoading]=useState(true);
  const[login,setLogin]=useState({email:'',password:''}),[form,setForm]=useState({name:'',slug:'',ownerEmail:'',ownerName:'',ownerPassword:''});
  const[notice,setNotice]=useState(''),[error,setError]=useState(''),[creating,setCreating]=useState(false),[confirm,setConfirm]=useState(null),[actionBusy,setActionBusy]=useState('');
  async function load(){
    setLoading(true);
    try{const m=await api('/api/platform/me');setMe(m.admin);const r=await api('/api/platform/restaurants');setRestaurants(r.restaurants||[]);setError('')}
    catch{setMe(null)}
    finally{setLoading(false)}
  }
  useEffect(()=>{load()},[]);
  async function doLogin(e){e.preventDefault();setError('');setLoading(true);try{await api('/api/platform/login',{method:'POST',body:JSON.stringify(login)});await load()}catch(e){setError(e.message);setLoading(false)}}
  async function createRestaurant(e){
    e.preventDefault();setCreating(true);setError('');setNotice('');
    try{const d=await api('/api/platform/restaurants',{method:'POST',body:JSON.stringify(form)});setNotice('Restaurant created successfully. Owner login: '+d.owner.email);setForm({name:'',slug:'',ownerEmail:'',ownerName:'',ownerPassword:''});await load()}
    catch(e){setError(e.message)}finally{setCreating(false)}
  }
  async function toggle(r){
    const status=r.status==='suspended'?'active':'suspended';
    if(status==='suspended'){setConfirm({title:'Suspend '+r.name+'?',text:'Customers and restaurant access will be blocked until you activate this restaurant again.',action:'Suspend restaurant',danger:true,run:()=>toggleNow(r,status)});return}
    await toggleNow(r,status);
  }
  async function toggleNow(r,status){
    setConfirm(null);setActionBusy(r.id);setError('');
    try{await api('/api/platform/restaurants/'+r.id,{method:'PATCH',body:JSON.stringify({status})});setNotice(status==='active'?r.name+' activated.':r.name+' suspended.');await load()}
    catch(e){setError(e.message)}finally{setActionBusy('')}
  }
  async function logout(){await api('/api/platform/logout',{method:'POST'}).catch(()=>{});setMe(null)}
  if(loading&&!me)return <div className="platformPage platformBoot"><div className="premiumLoader"><div className="loaderMark"><img src="/zelvon-mark.svg" alt="Zelvon"/></div><div className="loaderRing"/><b>ZELVON</b><span>Preparing your workspace…</span></div></div>;
  if(!me)return <div className="platformPage platformLoginPage"><form className="platformLogin platformCard" onSubmit={doLogin}>
    <div className="platformBrand">ZELVON</div><span className="loginEyebrow">PLATFORM CONTROL CENTER</span><h1>Welcome back</h1><p>Manage restaurants, plans and access from one secure workspace.</p>
    {error&&<div className="platformError">{error}</div>}
    <label>Email<input placeholder="Platform admin email" type="email" value={login.email} onChange={e=>setLogin({...login,email:e.target.value})} required/></label>
    <label>Password<input placeholder="Password" type="password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})} required/></label>
    <button type="submit" disabled={loading}>{loading?'Signing in…':'Sign in to platform'}</button>
  </form></div>;
  const active=restaurants.filter(r=>r.status==='active').length,trial=restaurants.filter(r=>r.status==='trial').length,suspended=restaurants.filter(r=>r.status==='suspended').length;
  return <div className="platformPage">
    <header className="platformHeader"><div className="platformHeaderBrand"><b>ZELVON</b><span>Platform Control Center</span></div><div className="platformHeaderRight"><span className="platformLiveDot">● Live</span><button onClick={logout}>Logout</button></div></header>
    <main className="platformMain">
      <div className="platformHero"><div><span>SAAS OPERATIONS</span><h1>Restaurants</h1><p>One platform. Isolated data. Centralized control.</p></div><div className="platformHeroBadge"><b>{active}</b><span>active tenants</span></div></div>
      {error&&<div className="platformError">{error}</div>}{notice&&<div className="platformSuccess">{notice}</div>}
      <section className="platformStats"><div><span>Total tenants</span><b>{restaurants.length}</b><small>All restaurants</small></div><div><span>Active</span><b>{active}</b><small>Operational</small></div><div><span>Trial</span><b>{trial}</b><small>Onboarding</small></div><div><span>Suspended</span><b>{suspended}</b><small>Access blocked</small></div></section>
      <section className="platformSection"><div className="platformSectionHead"><div><span className="sectionEyebrow">NEW TENANT</span><h2>Create restaurant</h2><p>Create an isolated tenant and owner account in one step.</p></div></div>
        <form className="platformForm" onSubmit={createRestaurant}>
          <label>Restaurant name<input placeholder="e.g. MUDCUPS CAFE" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} required/></label>
          <label>URL slug<input placeholder="e.g. mudcups-cafe" value={form.slug} onChange={e=>setForm({...form,slug:e.target.value.toLowerCase()})} required/></label>
          <label>Owner name<input placeholder="Optional" value={form.ownerName} onChange={e=>setForm({...form,ownerName:e.target.value})}/></label>
          <label>Owner email<input placeholder="owner@restaurant.com" type="email" value={form.ownerEmail} onChange={e=>setForm({...form,ownerEmail:e.target.value})} required/></label>
          <label>Temporary password<input placeholder="Minimum 8 characters" type="password" minLength="8" value={form.ownerPassword} onChange={e=>setForm({...form,ownerPassword:e.target.value})} required/></label>
          <button type="submit" disabled={creating}>{creating?'Creating tenant…':'Create restaurant'}</button>
        </form>
      </section>
      <section className="platformSection"><div className="platformSectionHead"><div><span className="sectionEyebrow">TENANT DIRECTORY</span><h2>Restaurants</h2><p>Each tenant keeps its menu, tables, staff, orders and sessions isolated.</p></div><span className="tenantCount">{restaurants.length} total</span></div>
        <div className="tenantList">{restaurants.length===0?<div className="platformEmpty">No restaurants yet.</div>:restaurants.map((r,i)=><article className="tenantCard" key={r.id} style={{animationDelay:(i*35)+'ms'}}>
          <div className="tenantIdentity"><div className="tenantAvatar">{(r.name||'R').slice(0,1).toUpperCase()}</div><div><strong>{r.name}</strong><span>{r.slug}</span></div></div>
          <div className="tenantMeta"><b className={'tenantStatus '+r.status}>{r.status}</b><span>{r.plan}</span><span>{r.table_count} tables</span><span>{r.order_count} orders</span></div>
          <button className={r.status==='suspended'?'tenantActivate':''} disabled={actionBusy===r.id} onClick={()=>toggle(r)}>{actionBusy===r.id?'Updating…':r.status==='suspended'?'Activate':'Suspend'}</button>
        </article>)}</div>
      </section>
    </main>
    <Confirm data={confirm} onClose={()=>setConfirm(null)} onConfirm={()=>confirm?.run()}/>
  </div>;
}
