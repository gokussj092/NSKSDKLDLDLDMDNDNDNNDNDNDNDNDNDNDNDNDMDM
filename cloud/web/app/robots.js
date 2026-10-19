export default function robots(){
  if(process.env.CLOUD_PUBLIC_SITE_INDEX!=="true")
    return {rules:[{userAgent:"*",disallow:"/"}]};
  return {rules:[{userAgent:"*",allow:"/",disallow:["/admin/","/api/admin/"]}]};
}
