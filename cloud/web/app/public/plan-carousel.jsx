"use client";
import {useCallback,useEffect,useRef,useState} from 'react';
import {money} from './shop-common.jsx';
const terms={base:null,'1m':1,'2m':2,'3m':3,'6m':6,'12m':12};
function titleFor(product,plan,lang){
 const es=lang==='es';
 if(product.id==='analysis-credits')return plan.credits+' '+(plan.credits===1?(es?'crédito':'credit'):(es?'créditos':'credits'));
 if(plan.id==='base')return product.id==='offline-3'?(es?'Pago único':'Lifetime'):(es?'Plan personalizado':'Custom plan');
 const n=terms[plan.id];return n===12?(es?'1 año':'1 year'):n+' '+(n===1?(es?'mes':'month'):(es?'meses':'months'));
}
function savings(product,plan,currency){
 if(product.id==='analysis-credits'){
  const unit=product.plans?.find(p=>p.id==='1c')?.prices?.[currency],value=plan.prices?.[currency];
  return unit&&value&&plan.credits>1?Math.max(0,Math.round((1-value/(unit*plan.credits))*100)):0;
 }
 const monthly=product.plans?.find(p=>p.id==='1m')?.prices?.[currency],count=terms[plan.id],value=plan.prices?.[currency];
 return monthly&&count>1&&value?Math.max(0,Math.round((1-value/(monthly*count))*100)):0;
}
export default function PlanCarousel({product,currency,lang,selected,onSelect}){
 const plans=(product?.plans||[]).filter(p=>p.id!=='base').concat(
   (product?.id==='offline-3'&&product.plans?.some(p=>p.id==='base'))?[product.plans.find(p=>p.id==='base')]:[]);
 const [idx,setIdx]=useState(1),[animated,setAnimated]=useState(true),[busy,setBusy]=useState(false);
 const timeout=useRef(null),gesture=useRef(null);
 const currentIndex=Math.max(0,plans.findIndex(p=>p.id===selected));
 const n=plans.length;
 useEffect(()=>{if(n){setAnimated(false);setIdx(currentIndex+1);setBusy(false);}},[currentIndex,n,product?.id,currency]);
 useEffect(()=>()=>clearTimeout(timeout.current),[]);
 const move=useCallback(delta=>{
  if(busy||n<2)return;
  setBusy(true);setAnimated(true);setIdx(value=>value+delta);
  timeout.current=setTimeout(()=>{
   const target=(currentIndex+delta+n)%n;
   setAnimated(false);setIdx(target+1);setBusy(false);
   onSelect(plans[target].id);
  },310);
 },[busy,n,currentIndex,onSelect,plans]);
 const select=useCallback(index=>{
  if(busy||index===currentIndex||!n)return;
  clearTimeout(timeout.current);setAnimated(true);setIdx(index+1);onSelect(plans[index].id);
 },[busy,currentIndex,onSelect,plans,n]);
 if(!n)return null;
 const cells=n===1?plans:[plans.at(-1),...plans,plans[0]];
 const es=lang==='es';
 function card(plan,slot){
  const cost=plan.prices?.[currency],save=savings(product,plan,currency);
  const credit=product.id==='analysis-credits',offline=product.id==='offline-3';
  const detail=credit?(es?'Un análisis completado por crédito':'One completed analysis per credit'):plan.days?(plan.days+' '+(es?'días de acceso':'days of access')):(es?'Vigencia del plan':'Plan duration');
  return <article key={slot} className={'sp-decode-plan sp-decode-plan-'+(credit?'credits':offline?'offline':'api')} aria-label={titleFor(product,plan,lang)}>
   <div className="sp-decode-plan-head"><span>SP-DECODE · {credit?(es?'CRÉDITOS':'CREDITS'):offline?'OFFLINE':'API'}</span><span>{String((slot-1+n)%n+1).padStart(2,'0')} / {String(n).padStart(2,'0')}</span></div>
   <div className="sp-decode-plan-body"><div><h3>{titleFor(product,plan,lang)}</h3><p>{credit?(es?'Análisis avanzado cuando lo necesites':'Advanced analysis when needed'):offline?(es?'Licencia para tus dispositivos':'License for your devices'):(es?'Acceso para tus integraciones':'Access for your integrations')}</p><span className="sp-decode-price-label">{es?'PRECIO DEL PLAN':'PLAN PRICE'}</span><strong className="sp-decode-plan-price">{cost?money(cost,currency,lang):'—'}</strong>{save>0&&<span className="sp-decode-plan-saving">{es?'Ahorra':'Save'} {save}%</span>}</div>
    <div className="sp-decode-plan-art" aria-hidden="true"><div className="sp-decode-plan-orbit"></div><div className="sp-decode-plan-icon"><img src="/icon.svg" width="68" height="68" alt=""/></div></div>
   </div>
   <div className="sp-decode-plan-foot"><span>{detail}</span><strong>{credit?(es?'Paquete personal':'Personal bundle'):offline?(es?'Hasta 3 dispositivos':'Up to 3 devices'):'API Key · IP'}</strong></div>
  </article>;
 }
 return <div className="sp-decode-carousel" aria-roledescription="carousel" aria-label={es?'Opciones del producto':'Product options'}>
  <div className="sp-decode-carousel-stage">
   <button className="sp-decode-carousel-arrow previous" type="button" aria-label={es?'Plan anterior':'Previous plan'} onClick={()=>move(-1)}>‹</button>
   <div className="sp-decode-carousel-window" tabIndex={0} aria-label={es?'Desliza para cambiar de plan':'Swipe to change plan'}
    onPointerDown={e=>{gesture.current={x:e.clientX,y:e.clientY};}}
    onPointerUp={e=>{const start=gesture.current;gesture.current=null;if(!start)return;const dx=e.clientX-start.x,dy=e.clientY-start.y;if(Math.abs(dx)>45&&Math.abs(dx)>Math.abs(dy))move(dx<0?1:-1);}}
    onPointerCancel={()=>{gesture.current=null;}}
    onKeyDown={e=>{if(e.key==='ArrowLeft'||e.key==='ArrowRight'){e.preventDefault();move(e.key==='ArrowLeft'?-1:1);}}}>
    <div className="sp-decode-carousel-track" style={{transform:'translate3d(-'+idx*100+'%,0,0)',transition:animated?'transform 300ms cubic-bezier(.2,.8,.3,1)':'none'}}>
     {cells.map((plan,i)=><div className="sp-decode-carousel-slide" key={plan.id+'-'+i}>{card(plan,i)}</div>)}
    </div>
   </div>
   <button className="sp-decode-carousel-arrow next" type="button" aria-label={es?'Plan siguiente':'Next plan'} onClick={()=>move(1)}>›</button>
  </div>
  <div className="sp-decode-carousel-dots" role="group" aria-label={es?'Seleccionar plan':'Select plan'}>
   {plans.map((p,i)=><button key={p.id} type="button" aria-current={i===currentIndex?'true':undefined} aria-label={titleFor(product,p,lang)} onClick={()=>select(i)} className={i===currentIndex?'active':''}/>)}
  </div>
  <p className="sp-decode-carousel-hint">{es?'Desliza para ver otros planes':'Swipe to explore other plans'}</p>
 </div>;
}
