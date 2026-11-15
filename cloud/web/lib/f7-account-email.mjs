/**
 * F7-A1-P04: plaintext-only bilingual security-email templates.
 * Not an SMTP/Gmail client; no messages are sent by importing this module.
 * Never use untrusted HTML in an admin mailbox or email template.
 */
import {normalizeDisplayName} from "./f7-account-identity.mjs";

const SUPPORT="soporte@spdecode.xyz";
const REQUIRED_CODE=/^[0-9]{6}$/;
const EVENTS=new Set([
  "verify_email", "password_reset", "new_signin", "password_changed",
  "email_changed",
]);

function safeName(value) {
  return normalizeDisplayName(value) ?? (typeof value==="string" ? "usuario" : "usuario");
}

export function formatSecurityEmail({type,locale="es",name,code,when}) {
  if(!EVENTS.has(type)) throw Error("UNKNOWN_SECURITY_EVENT");
  if(!["es","en"].includes(locale)) throw Error("UNSUPPORTED_LOCALE");
  const isCode=type==="verify_email" || type==="password_reset";
  if(isCode && (typeof code!=="string" || !REQUIRED_CODE.test(code)))
    throw Error("INVALID_CODE");
  if(!isCode && code!==undefined)throw Error("CODE_NOT_ALLOWED_FOR_EVENT");
  const display=safeName(name);
  let subject,lines;
  if(locale==="es"){
    const data={
      verify_email:["SP-DECODE — Verifica tu correo",
       ["Hola, "+display+".","Tu código de verificación es: "+code,
        "Caduca en 10 minutos. No lo compartas con nadie.",
        "Si no solicitaste crear una cuenta, ignora este mensaje."]],
      password_reset:["SP-DECODE — Restablecimiento de contraseña",
       ["Hola, "+display+".","Se solicitó recuperar el acceso a tu cuenta.",
        "Código de recuperación: "+code,
        "Caduca en 10 minutos. No lo compartas con nadie.",
        "Si no fuiste tú, no introduzcas este código."]],
      new_signin:["SP-DECODE — Nuevo inicio de sesión",
       ["Hola, "+display+".","Se detectó un nuevo inicio de sesión en tu cuenta.",
        "Si no fuiste tú, cambia tu contraseña, revisa las sesiones y contacta a soporte."]],
      password_changed:["SP-DECODE — Contraseña modificada",
       ["Hola, "+display+".","Se cambió la contraseña de tu cuenta.",
        "Si no autorizaste este cambio, solicita recuperación inmediatamente y contacta a soporte."]],
      email_changed:["SP-DECODE — Correo modificado",
       ["Hola, "+display+".","Se cambió el correo asociado a tu cuenta.",
        "Si no lo autorizaste, contacta inmediatamente a soporte."]],
    };
    [subject,lines]=data[type];
  }else{
    const data={
      verify_email:["SP-DECODE — Verify your email",
       ["Hello, "+display+".","Your verification code is: "+code,
        "It expires in 10 minutes. Never share it.",
        "If you didn't create an account, ignore this message."]],
      password_reset:["SP-DECODE — Password reset",
       ["Hello, "+display+".","A request to reset your account password was made.",
        "Recovery code: "+code,
        "It expires in 10 minutes. Never share it.",
        "If this wasn't you, do not enter this code."]],
      new_signin:["SP-DECODE — New sign-in",
       ["Hello, "+display+".","A new sign-in was detected on your account.",
        "If this wasn't you, change your password, review active sessions and contact support."]],
      password_changed:["SP-DECODE — Password changed",
       ["Hello, "+display+".","Your account password has been changed.",
        "If you didn't authorize this, start account recovery and contact support immediately."]],
      email_changed:["SP-DECODE — Email address changed",
       ["Hello, "+display+".","Your account email address has been changed.",
        "If you didn't authorize this, contact support immediately."]],
    };
    [subject,lines]=data[type];
  }
  if(when!==undefined){
    if(!(when instanceof Date) || !Number.isFinite(when.getTime()))
      throw Error("INVALID_EVENT_TIME");
    lines=[...lines,(locale==="es"?"Fecha UTC: ":"UTC time: ")+when.toISOString()];
  }
  lines.push((locale==="es"?"Soporte: ":"Support: ")+SUPPORT);
  lines.push("https://spdecode.xyz/privacy");
  const text=lines.join("\n\n");
  return Object.freeze({
    type,locale,subject,text,format:"text/plain; charset=utf-8",
    category:"ESSENTIAL_ACCOUNT_SECURITY",
    marketing:false,hasAttachments:false,
    // SMTP transport may use a verified security@ domain sender in the future.
    senderConfigured:false,
  });
}
