import {ImageResponse} from "next/og";
export const size={width:1200,height:630};
export const contentType="image/png";
export const alt="SP-DECODE para Android — Ghost Developer";
export default function Image(){
  return new ImageResponse(<div style={{display:"flex",width:"100%",height:"100%",background:"#000",color:"#fff",alignItems:"center",justifyContent:"center",gap:48,padding:80}}>
    <div style={{display:"flex",width:190,height:190,borderRadius:42,background:"#242424",alignItems:"center",justifyContent:"center"}}>
      <svg width="134" height="134" viewBox="0 0 24 24">
        <path d="M12,2 L21,5 L21,11.5 C21,17.2 17.4,21.5 12,23 C6.6,21.5 3,17.2 3,11.5 L3,5 Z" fill="#fff"/>
        <path d="M12,4.4 L18.8,6.8 L18.8,11.5 C18.8,15.8 16.2,18.7 12,20 C7.8,18.7 5.2,15.8 5.2,11.5 L5.2,6.8 Z" fill="#000"/>
        <path d="M9.4,11.8 L11.2,13.6 L15.5,9.3 L17,10.8 L11.2,16.6 L7.9,13.3 Z" fill="#fff"/>
      </svg>
    </div>
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div style={{fontSize:92,fontWeight:800,letterSpacing:-5}}>SP-DECODE</div>
      <div style={{fontSize:31,color:"#c4c4c4"}}>Configuration decoder · Android</div>
      <div style={{fontSize:23,color:"#9a9a9a"}}>Ghost Developer · spdecode.xyz</div>
    </div>
  </div>,size);
}
