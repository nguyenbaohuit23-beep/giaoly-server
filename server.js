const express=require('express'),{createClient}=require('@libsql/client'),crypto=require('crypto');
const E=process.env,SECRET=E.SESSION_SECRET;
if(!SECRET||!E.ADMIN_PASS||!E.HELPER_PASS){console.error('Thiếu SESSION_SECRET, ADMIN_PASS hoặc HELPER_PASS (xem README.md).');process.exit(1)}
const USERS={[E.ADMIN_USER||'giaolyvien']:{pass:E.ADMIN_PASS,role:'admin',name:'Giáo lý viên'},[E.HELPER_USER||'phulop']:{pass:E.HELPER_PASS,role:'helper',name:'Phụ lớp'}};
const db=createClient({url:E.TURSO_URL||'file:'+(E.DB_FILE||'data.db'),authToken:E.TURSO_TOKEN});
const ready=db.executeMultiple('CREATE TABLE IF NOT EXISTS doc(id INTEGER PRIMARY KEY,json TEXT);CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,user TEXT,text TEXT)');
const DEF={year:'2026-2027',students:[],att:{},set:{w:[1,2,3],A:8,B:6.5,C:5,min:5,mass:80}};
const get=async()=>{const r=await db.execute('SELECT json FROM doc WHERE id=1');return r.rows.length?JSON.parse(r.rows[0].json):structuredClone(DEF)};
const save=(d,u,L)=>{const ts=new Date().toISOString();return db.batch([{sql:'INSERT INTO doc(id,json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json',args:[JSON.stringify(d)]},...L.map(x=>({sql:'INSERT INTO log(ts,user,text) VALUES(?,?,?)',args:[ts,u,x]}))],'write')};
let chain=Promise.resolve();const lock=f=>{const r=chain.then(f);chain=r.catch(()=>{});return r};
const A=f=>(q,r,n)=>Promise.resolve(f(q,r,n)).catch(e=>{console.error(e);r.status(500).json({error:'Lỗi máy chủ, vui lòng thử lại'})});
const h=s=>crypto.createHash('sha256').update(String(s)).digest();
const same=(a,b)=>crypto.timingSafeEqual(h(a),h(b));
const mac=b=>crypto.createHmac('sha256',SECRET).update(b).digest('base64url');
const sign=p=>{const b=Buffer.from(JSON.stringify(p)).toString('base64url');return b+'.'+mac(b)};
const verify=t=>{try{const[b,s]=t.split('.'),o=mac(b);if(s.length!==o.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(o)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch(e){return null}};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'2mb'}));
const tries={};
app.post('/api/login',(req,res)=>{const ip=req.ip,t=tries[ip]=(tries[ip]||[]).filter(x=>x>Date.now()-9e5);
  if(t.length>=10)return res.status(429).json({error:'Thử quá nhiều lần, vui lòng đợi 15 phút'});
  const u=USERS[req.body.u];if(!u||!same(u.pass,req.body.p||'')){t.push(Date.now());return res.status(400).json({error:'Sai tên đăng nhập hoặc mật khẩu'})}
  res.setHeader('Set-Cookie',`sid=${sign({u:req.body.u,exp:Date.now()+30*864e5})}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000${req.secure?'; Secure':''}`);res.json({ok:1})});
app.post('/api/logout',(q,r)=>{r.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/');r.json({ok:1})});
const auth=(req,res,next)=>{const c=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid=')),p=c&&verify(c.slice(4)),u=p&&USERS[p.u];
  if(!u)return res.status(401).json({error:'Chưa đăng nhập'});req.u=u;next()};
const admin=(req,res,next)=>req.u.role==='admin'?next():res.status(403).json({error:'Không có quyền'});
const view=(d,role)=>role==='admin'?d:{...d,students:d.students.map(({id,saint,name,g})=>({id,saint,name,g}))};
const full=s=>s?(s.saint?s.saint+' ':'')+s.name:'?';
const LB={m:'Miệng',q:'15 phút',t:'Thi'},CL={P:'Có mặt',A:'Vắng có phép',U:'Vắng không phép','':'trống'};
app.get('/api/data',auth,A(async(q,r)=>r.json({me:{name:q.u.name,role:q.u.role},doc:view(await get(),q.u.role)})));
app.post('/api/op',auth,A((req,res)=>lock(async()=>{const d=await get(),L=[],ops=Array.isArray(req.body)?req.body.slice(0,200):[];
  for(const o of ops){const s=d.students.find(x=>x.id===o.id);
    if(o.t==='g'){if(!s||![1,2].includes(o.hk)||!LB[o.k])continue;const v=o.v===''?'':Math.min(10,Math.max(0,+o.v));if(v!==''&&isNaN(v))continue;
      s.g=s.g||{};s.g[o.hk]=s.g[o.hk]||{};const old=s.g[o.hk][o.k];if(old===v)continue;s.g[o.hk][o.k]=v;
      L.push(`Điểm ${LB[o.k]} HK${o.hk} của ${full(s)}: ${old===undefined||old===''?'trống':old} → ${v===''?'trống':v}`)}
    else if(o.t==='att'){if(!s||!/^\d{4}-\d\d-\d\d$/.test(o.day)||!['c','s','t'].includes(o.k))continue;
      if(o.k==='c'&&!(o.v in CL))continue;const v=o.k==='c'?o.v:!!o.v;
      const r=((d.att[o.day]=d.att[o.day]||{})[o.id]=d.att[o.day][o.id]||{}),old=r[o.k];if(old===v)continue;r[o.k]=v;
      const nm={c:'Học giáo lý',s:'Lễ Chúa nhật',t:'Lễ thứ Năm'}[o.k],f=x=>o.k==='c'?CL[x||'']:x?'có':'không';
      L.push(`Điểm danh ${o.day.split('-').reverse().join('/')} · ${nm} của ${full(s)}: ${f(old)} → ${f(v)}`)}
    else if(o.t==='delday'&&req.u.role==='admin'&&d.att[o.day]){delete d.att[o.day];L.push('Xóa điểm danh ngày '+o.day)}}
  await save(d,req.u.name,L);res.json({ok:1})})));
const FL=['saint','name','dob','parish','father','fphone','mother','mphone','addr','note'],num=(x,f)=>isFinite(+x)&&x!==''?+x:f;
app.post('/api/admin',auth,admin,A((req,res)=>lock(async()=>{const d=await get(),L=[],b=req.body||{},old=new Map(d.students.map(s=>[s.id,s]));
  const before=JSON.stringify([d.year,d.set,d.students.map(({g,...p})=>p)]);
  d.year=String(b.year||d.year).slice(0,20);
  if(b.set){const s=b.set;d.set={w:[0,1,2].map(i=>num(s.w&&s.w[i],1)||1),A:num(s.A,8),B:num(s.B,6.5),C:num(s.C,5),min:num(s.min,5),mass:num(s.mass,80)}}
  d.students=(b.students||[]).slice(0,300).map(p=>{const o={id:String(p.id).slice(0,40)};FL.forEach(k=>o[k]=String(p[k]||'').slice(0,200));o.g=(old.get(o.id)||{}).g||{};return o});
  const ids=new Set(d.students.map(s=>s.id));Object.values(d.att).forEach(a=>Object.keys(a).forEach(i=>{if(!ids.has(i))delete a[i]}));
  if(before!==JSON.stringify([d.year,d.set,d.students.map(({g,...p})=>p)]))L.push('Cập nhật hồ sơ/cài đặt');
  await save(d,req.u.name,L);res.json({doc:d})})));
app.post('/api/restore',auth,admin,A((req,res)=>lock(async()=>{const b=req.body;if(!b||!Array.isArray(b.students)||!b.set||!b.att)return res.status(400).json({error:'File sao lưu không hợp lệ'});
  await save(b,req.u.name,['Khôi phục dữ liệu từ file sao lưu']);res.json({ok:1})})));
app.get('/api/log',auth,admin,A(async(q,r)=>{const x=await db.execute('SELECT ts,user,text FROM log ORDER BY id DESC LIMIT 300');r.json(x.rows.map(w=>({ts:w.ts,user:w.user,text:w.text})))}));
app.use(express.static(__dirname+'/public'));
ready.then(()=>app.listen(E.PORT||3000,E.HOST||'0.0.0.0',()=>console.log('Chạy tại cổng '+(E.PORT||3000)))).catch(e=>{console.error('Không kết nối được cơ sở dữ liệu:',e.message);process.exit(1)});