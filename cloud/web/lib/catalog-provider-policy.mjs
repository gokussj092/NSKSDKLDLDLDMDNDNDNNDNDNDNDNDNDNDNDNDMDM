/** Operator defaults for documented upstream limitations; no decoder changes. */
export const PENDING_CATALOGS=Object.freeze({
  "jetroi":"Clave nueva del catálogo remoto pendiente; los archivos siguen disponibles.",
  "marvs-ssh":"Clave nueva del catálogo remoto pendiente; los archivos siguen disponibles.",
  "reg-tunnel":"Clave nueva del catálogo remoto pendiente; los archivos siguen disponibles.",
  "rnv-tunnel-vpn":"Clave del catálogo remoto pendiente de analizar en la app actualizada.",
  "ignix-vpn-max":"Descifrado y token del catálogo pendientes de captura autorizada.",
  "yla-vpn":"Firma del proveedor pendiente de captura autorizada en un teléfono real.",
  "xj-vpn":"Requiere una captura autorizada con la app de Play y su identidad real.",
  "vertexsnipher":"Requiere una captura autorizada con la app de Play y su identidad real.",
  "docnet-vpn":"Clave de los campos de configuración pendiente; el resultado sigue siendo parcial.",
});
export const catalogDefaultEnabled=id=>!Object.hasOwn(PENDING_CATALOGS,id);
