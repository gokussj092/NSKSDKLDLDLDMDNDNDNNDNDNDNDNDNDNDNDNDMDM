/** C6 information site + API; no administrative caching or framing. */
export default {
  poweredByHeader:false,
  skipTrailingSlashRedirect:true,
  skipProxyUrlNormalize:true,
  reactStrictMode:true,
  async headers(){
    return [
      {source:"/(.*)",headers:[
        {key:"X-Content-Type-Options",value:"nosniff"},
        {key:"Referrer-Policy",value:"no-referrer"},
        {key:"X-Frame-Options",value:"DENY"},
        {key:"Permissions-Policy",value:"camera=(), microphone=(), geolocation=()"},
      ]},
      {source:"/admin/:path*",headers:[
        {key:"Cache-Control",value:"private, no-store, max-age=0"},
        {key:"X-Robots-Tag",value:"noindex, nofollow"},
      ]},
      {source:"/api/admin/:path*",headers:[
        {key:"Cache-Control",value:"private, no-store, max-age=0"},
        {key:"X-Robots-Tag",value:"noindex, nofollow"},
      ]},
      {source:"/account",headers:[{key:"Cache-Control",value:"private, no-store, max-age=0"},{key:"X-Robots-Tag",value:"noindex, nofollow"}]},
      ...["/login","/orders","/receipts","/products"].map(source=>({source,headers:[{key:"Cache-Control",value:"private, no-store, max-age=0"},{key:"X-Robots-Tag",value:"noindex, nofollow"}]})),
      {source:"/api/auth/:path*",headers:[{key:"Cache-Control",value:"private, no-store, max-age=0"}]},
      {source:"/api/account/:path*",headers:[{key:"Cache-Control",value:"private, no-store, max-age=0"}]},
      {source:"/api/store/:path*",headers:[{key:"Cache-Control",value:"private, no-store, max-age=0"}]},
    ];
  },
};
