import React,{useEffect,useState} from 'react';
import './platform.css';

const API='https://qr-restaurant-os-api.onrender.com';

async function api(path,options={}){
  const r=await fetch(API+path,{
    credentials:'include',
    headers:{'Content-Type':'application/json',...(options.headers||{})},
    ...options
  });
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error||'Request failed');
  return data;
}

export default function Platform(){
  const [me,setMe]=useState(null);
  const [restaurants,setRestaurants]=useState([]);
  const [loading,setLoading]=useState(true);
  const [login,setLogin]=useState({email:'',password:''});
  const [form,setForm]=useState({name:'',slug:'',ownerEmail:'',ownerName:'',ownerPassword:''});
  const [notice,setNotice]=useState('');
  const [error,setError]=useState('');
  const [creating,setCreating]=useState(false);

  async function load(){
    setLoading(true);
    try{
      const m=await api('/api/platform/me');
      setMe(m.admin);
      const r=await api('/api/platform/restaurants');
      setRestaurants(r.restaurants||[]);
      setError('');
    }catch(e){
      setMe(null);
    }finally{
      setLoading(false);
    }
  }

  useEffect(()=>{load()},[]);

  async function doLogin(e){
    e.preventDefault();
    setError('');
    try{
      await api('/api/platform/login',{method:'POST',body:JSON.stringify(login)});
      await load();
    }catch(e){setError(e.message)}
  }

  async function createRestaurant(e){
    e.preventDefault();
    setCreating(true);
    setError('');
    setNotice('');
    try{
      const d=await api('/api/platform/restaurants',{method:'POST',body:JSON.stringify(form)});
      setNotice('Created '+d.restaurant.name+'. Owner login: '+d.owner.email);
      setForm({name:'',slug:'',ownerEmail:'',ownerName:'',ownerPassword:''});
      await load();
    }catch(e){setError(e.message)}
    finally{setCreating(false)}
  }

  async function toggle(r){
    const status=r.status==='suspended'?'active':'suspended';
    try{
      await api('/api/platform/restaurants/'+r.id,{method:'PATCH',body:JSON.stringify({status})});
      await load();
    }catch(e){setError(e.message)}
  }

  async function logout(){
    await api('/api/platform/logout',{method:'POST'}).catch(()=>{});
    setMe(null);
  }

  if(loading) return <div className="platformPage"><div className="platformCard">Loading platform…</div></div>;

  if(!me) return (
    <div className="platformPage">
      <form className="platformLogin platformCard" onSubmit={doLogin}>
        <div className="platformBrand">MENUTABLE</div>
        <h1>Platform Admin</h1>
        <p>Manage restaurants from one central dashboard.</p>
        {error&&<div className="platformError">{error}</div>}
        <input placeholder="Platform admin email" type="email" value={login.email} onChange={e=>setLogin({...login,email:e.target.value})} required/>
        <input placeholder="Password" type="password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})} required/>
        <button type="submit">Sign in</button>
      </form>
    </div>
  );

  return (
    <div className="platformPage">
      <header className="platformHeader">
        <div><b>MENUTABLE</b><span>Platform Control Center</span></div>
        <button onClick={logout}>Logout</button>
      </header>
      <main className="platformMain">
        <div className="platformTitle">
          <div><span>SAAS OPERATIONS</span><h1>Restaurants</h1><p>One platform. Separate restaurant data and operations.</p></div>
        </div>

        {error&&<div className="platformError">{error}</div>}
        {notice&&<div className="platformSuccess">{notice}</div>}

        <section className="platformStats">
          <div><span>Total</span><b>{restaurants.length}</b></div>
          <div><span>Active</span><b>{restaurants.filter(r=>r.status==='active').length}</b></div>
          <div><span>Trial</span><b>{restaurants.filter(r=>r.status==='trial').length}</b></div>
          <div><span>Suspended</span><b>{restaurants.filter(r=>r.status==='suspended').length}</b></div>
        </section>

        <section className="platformSection">
          <div className="platformSectionHead"><div><h2>Add restaurant</h2><p>Create an isolated restaurant tenant and its owner account.</p></div></div>
          <form className="platformForm" onSubmit={createRestaurant}>
            <input placeholder="Restaurant name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} required/>
            <input placeholder="Slug e.g. abc-cafe" value={form.slug} onChange={e=>setForm({...form,slug:e.target.value.toLowerCase()})} required/>
            <input placeholder="Owner name (optional)" value={form.ownerName} onChange={e=>setForm({...form,ownerName:e.target.value})}/>
            <input placeholder="Owner email" type="email" value={form.ownerEmail} onChange={e=>setForm({...form,ownerEmail:e.target.value})} required/>
            <input placeholder="Temporary owner password" type="password" minLength="8" value={form.ownerPassword} onChange={e=>setForm({...form,ownerPassword:e.target.value})} required/>
            <button type="submit" disabled={creating}>{creating?'Creating…':'Create restaurant'}</button>
          </form>
        </section>

        <section className="platformSection">
          <div className="platformSectionHead"><div><h2>Tenants</h2><p>Each restaurant has its own menu, tables, staff, orders and sessions.</p></div></div>
          <div className="tenantList">
            {restaurants.map(r=>(
              <article className="tenantCard" key={r.id}>
                <div><strong>{r.name}</strong><span>{r.slug}</span></div>
                <div className="tenantMeta">
                  <b className={'tenantStatus '+r.status}>{r.status}</b>
                  <span>{r.plan}</span><span>{r.table_count} tables</span><span>{r.order_count} orders</span>
                </div>
                <button onClick={()=>toggle(r)}>{r.status==='suspended'?'Activate':'Suspend'}</button>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
