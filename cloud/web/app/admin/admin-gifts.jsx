"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';

function formatDate(date){if(!date)return 'Sin caducidad';
  try{return new Date(date).toLocaleString('es-MX',{dateStyle:'medium',timeStyle:'short'});}
  catch{return '—';}
}
function avatarSource(value){
  if(typeof value!=='string')return null;
  if(/^https:\/\/lh[3-6]\.googleusercontent\.com\//.test(value))return value;
  if(/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(value)&&value.length<115000)
    return value;
  return null;
}
function benefit(row){
  if(row.kind==='credits')return row.credits+' créditos APK';
  if(row.kind==='ads-free')return row.days+' días sin anuncios';
  return row.days+' días SP-DECODE Offline';
}
export default function AdminGiftCodes(){
  const router=useRouter();
  const [state,setState]=useState({codes:[],redemptions:[]});
  const [form,setForm]=useState({title:'',kind:'credits',credits:5,days:30,maxUses:1,expiresAt:''});
  const [generated,setGenerated]=useState('');
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  const load=useCallback(async()=>{
    const response=await fetch('/api/admin/gifts',{cache:'no-store',credentials:'same-origin'});
    if(response.status===401){router.replace('/admin/login');return;}
    if(!response.ok)throw Error('No se pudieron consultar los códigos de regalo.');
    setState(await response.json());
  },[router]);
  useEffect(()=>{load().catch(e=>setError(e.message));},[load]);
  async function mutate(body){
    setBusy(true);setError('');setNotice('');
    try{
      const response=await fetch('/api/admin/gifts',{method:'POST',cache:'no-store',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
        body:JSON.stringify(body)});
      const data=await response.json();
      if(!response.ok)throw Error(data?.error?.code==='INVALID_GIFT'?
        'Revisa la duración, usos y vencimiento del regalo.':
        'No se pudo completar la operación. Comprueba la sesión y el servidor.');
      if(body.action==='create'){setGenerated(data.code);setNotice('Código creado. Cópialo ahora: por seguridad no podrá consultarse después.');}
      else setNotice('El código quedó deshabilitado para futuros canjes.');
      await load();
    }catch(e){setError(e.message);}finally{setBusy(false);}
  }
  function submit(e){
    e.preventDefault();setGenerated('');
    const base={action:'create',kind:form.kind,title:form.title.trim(),
      maxUses:Number(form.maxUses)};
    if(form.kind==='credits')base.credits=Number(form.credits);
    else base.days=Number(form.days);
    if(form.expiresAt)base.expiresAt=new Date(form.expiresAt).toISOString();
    mutate(base);
  }
  return <div className="sp-admin-commerce sp-gifts-admin">
    <header className="sp-admin-commerce-hero"><div>
      <span className="sp-admin-commercial-kicker">SP-DECODE · BENEFICIOS</span>
      <h2>Códigos de regalo</h2>
      <p>Genera recompensas individuales o de varios usos y consulta quién las canjeó.</p>
    </div><img src="/icon.svg" width="58" height="58" alt=""/></header>
    {error&&<p className="form-message error" role="alert">{error}</p>}
    {notice&&<p className="form-message" role="status">{notice}</p>}
    {generated&&<section className="admin-card sp-gift-result"><h2>Código generado</h2>
      <div className="sp-gift-code"><code>{generated}</code>
        <button className="button" type="button" onClick={()=>navigator.clipboard.writeText(generated)}>Copiar</button>
      </div><p className="muted">Guárdalo en un lugar seguro. El servidor conserva solamente su huella criptográfica.</p>
      <button type="button" className="button" onClick={()=>setGenerated('')}>Ocultar código</button>
    </section>}
    <section className="admin-card"><h2>Crear regalo</h2>
      <form onSubmit={submit} className="sp-gift-form">
        <label>Descripción interna<input required maxLength={80} minLength={2}
          placeholder="Ej. Sorteo comunidad — noviembre" value={form.title}
          onChange={e=>setForm(x=>({...x,title:e.target.value}))}/></label>
        <label>Beneficio<select value={form.kind}
          onChange={e=>setForm(x=>({...x,kind:e.target.value}))}>
          <option value="credits">Créditos de análisis APK</option>
          <option value="ads-free">Acceso Online sin anuncios</option>
          <option value="offline-3">Licencia SP-DECODE Offline</option>
        </select></label>
        {form.kind==='credits'?<label>Créditos por usuario<input type="number" min={1} max={1000}
          required value={form.credits} onChange={e=>setForm(x=>({...x,credits:e.target.value}))}/></label>
        :<label>Días de acceso por usuario<input type="number" min={1} max={3650} required
          value={form.days} onChange={e=>setForm(x=>({...x,days:e.target.value}))}/>
          <small>30 = 1 mes, 60 = 2 meses, 365 = 1 año.</small></label>}
        <label>Número máximo de canjes<input type="number" min={1} max={10000} required
          value={form.maxUses} onChange={e=>setForm(x=>({...x,maxUses:e.target.value}))}/>
          <small>Una misma cuenta solo puede usar cada código una vez.</small></label>
        <label>Caducidad del código (opcional)<input type="datetime-local"
          value={form.expiresAt} onChange={e=>setForm(x=>({...x,expiresAt:e.target.value}))}/></label>
        <button type="submit" className="button" disabled={busy}>{busy?'Guardando…':'Generar código seguro'}</button>
      </form>
    </section>
    <section className="admin-card"><h2>Códigos creados</h2>
      {!state.codes?.length?<p className="muted">No hay códigos de regalo.</p>:
      <div className="sp-gift-list">{state.codes.map(item=><article key={item.id} className="sp-gift-row">
        <div><strong>{item.title}</strong>
          <p className="muted">{benefit(item)} · {item.used}/{item.max_uses} canjes</p>
          <small className="muted">Creado: {formatDate(item.created_at)} · Vence: {formatDate(item.expires_at)}</small>
        </div>
        <div><span className={item.enabled?'sp-gift-live':'sp-gift-off'}>{item.enabled?'Activo':'Desactivado'}</span>
          {item.enabled&&<button type="button" className="button" disabled={busy}
            onClick={()=>{if(window.confirm('¿Deshabilitar futuros canjes?'))mutate({action:'disable',id:item.id});}}>
            Deshabilitar</button>}
        </div>
      </article>)}</div>}
    </section>
    <section className="admin-card"><h2>Usuarios que canjearon regalos</h2>
      {!state.redemptions?.length?<p className="muted">Todavía no hay canjes.</p>:
      <div className="sp-gift-list">{state.redemptions.map(item=><article key={item.id}
        className="sp-gift-row">
        <div className="sp-gift-account">{avatarSource(item.avatar)?
          <img className="sp-gift-avatar" src={avatarSource(item.avatar)} alt="" width="47" height="47"/>:
          <span className="sp-gift-avatar sp-gift-initial">{item.name?.slice(0,1)||'?'}</span>}
          <div><strong>{item.name||'Cuenta eliminada'}</strong>
            <div className="muted">{item.username?'@'+item.username:'—'}</div>
            <small className="muted">ID permanente: {item.account_id}</small>
          </div>
        </div>
        <div><strong>{item.title}</strong><p className="muted">{formatDate(item.created_at)}</p></div>
      </article>)}</div>}
    </section>
  </div>;
}
