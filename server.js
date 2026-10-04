const express=require('express'),{createClient}=require('@libsql/client'),crypto=require('crypto');
const E=process.env,SECRET=E.SESSION_SECRET;
if(!SECRET){console.error('Thiếu biến SESSION_SECRET (xem README.md).');process.exit(1)}
const db=createClient({url:E.TURSO_URL||'file:'+(E.DB_FILE||'data.db'),authToken:E.TURSO_TOKEN});
const DEFSET={w:[1,2,3],A:8,B:6.5,C:5,min:5,mass:80};
const Q1=async(sql,args=[])=>(await db.execute({sql,args})).rows;
const hashPw=p=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.scryptSync(p,s,64).toString('hex')};
const checkPw=(p,h)=>{try{const[s,x]=h.split(':'),y=crypto.scryptSync(p,s,64),z=Buffer.from(x,'hex');return y.length===z.length&&crypto.timingSafeEqual(y,z)}catch(e){return false}};
const ready=(async()=>{
  await db.executeMultiple(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL,class_id INTEGER,pass TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS docs(class_id INTEGER NOT NULL,year TEXT NOT NULL,json TEXT NOT NULL,PRIMARY KEY(class_id,year));
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS doc(id INTEGER PRIMARY KEY,json TEXT);
CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,user TEXT,text TEXT)`);
  for(const s of ['ALTER TABLE log ADD COLUMN class_id INTEGER','ALTER TABLE log ADD COLUMN year TEXT']){try{await db.execute(s)}catch(e){}}
  if((await Q1('SELECT COUNT(*) c FROM users'))[0].c>0)return;
  if(!E.SYSADMIN_PASS||E.SYSADMIN_PASS.length<8)throw new Error('Lần chạy đầu cần biến SYSADMIN_PASS (tối thiểu 8 ký tự).');
  const ins=(u,nm,role,cid,pw)=>db.execute({sql:'INSERT INTO users(username,name,role,class_id,pass) VALUES(?,?,?,?,?)',args:[u,nm,role,cid,hashPw(pw)]});
  await ins((E.SYSADMIN_USER||'sysadmin').toLowerCase(),'Quản trị hệ thống','sysadmin',null,E.SYSADMIN_PASS);
  const old=await Q1('SELECT json FROM doc WHERE id=1');
  if(old.length){const d=JSON.parse(old[0].json),yr=d.year||'2026-2027';
    const r=await db.execute({sql:'INSERT INTO classes(name) VALUES(?)',args:[E.CLASS_NAME||'Sơ cấp 1 B']}),cid=Number(r.lastInsertRowid);
    await db.execute({sql:'INSERT INTO docs(class_id,year,json) VALUES(?,?,?)',args:[cid,yr,JSON.stringify({students:d.students||[],att:d.att||{}})]});
    await db.execute({sql:"INSERT INTO kv(k,v) VALUES('settings',?)",args:[JSON.stringify(d.set||DEFSET)]});
    await db.execute({sql:'UPDATE log SET class_id=?,year=? WHERE class_id IS NULL',args:[cid,yr]});
    for(const[u,nm,role,pw]of[['giaolyvien','Giáo lý viên','teacher',E.ADMIN_PASS],['phulop','Phụ lớp','helper',E.HELPER_PASS]]){
      if(pw&&pw.length>=8)await ins(u,nm,role,cid,pw);else console.warn('Bỏ qua tài khoản '+u+' (thiếu mật khẩu hoặc dưới 8 ký tự). Hãy tạo lại trong thẻ Quản trị.')}}
})();
const getSet=async()=>{const r=await Q1("SELECT v FROM kv WHERE k='settings'");return r.length?JSON.parse(r[0].v):DEFSET};
const getDoc=async(c,y)=>{const r=await Q1('SELECT json FROM docs WHERE class_id=? AND year=?',[c,y]);return r.length?JSON.parse(r[0].json):null};
const years=async c=>(await Q1('SELECT year FROM docs WHERE class_id=? ORDER BY year DESC',[c])).map(r=>r.year);
const save=(c,y,d,u,L,lc=c)=>{const ts=new Date().toISOString();return db.batch([{sql:'INSERT INTO docs(class_id,year,json) VALUES(?,?,?) ON CONFLICT(class_id,year) DO UPDATE SET json=excluded.json',args:[c,y,JSON.stringify(d)]},...L.map(x=>({sql:'INSERT INTO log(ts,user,text,class_id,year) VALUES(?,?,?,?,?)',args:[ts,u,x,lc,y]}))],'write')};
const glog=(u,t)=>db.execute({sql:'INSERT INTO log(ts,user,text,class_id,year) VALUES(?,?,?,NULL,NULL)',args:[new Date().toISOString(),u,t]});
let chain=Promise.resolve();const lock=f=>{const r=chain.then(f);chain=r.catch(()=>{});return r};
const A=f=>(q,r,n)=>Promise.resolve(f(q,r,n)).catch(e=>{console.error(e);if(!r.headersSent)r.status(500).json({error:'Lỗi máy chủ, vui lòng thử lại'})});
const mac=b=>crypto.createHmac('sha256',SECRET).update(b).digest('base64url');
const sign=p=>{const b=Buffer.from(JSON.stringify(p)).toString('base64url');return b+'.'+mac(b)};
const verify=t=>{try{const[b,s]=t.split('.'),o=mac(b);if(s.length!==o.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(o)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch(e){return null}};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'2mb'}));
const tries={};
app.post('/api/login',A(async(req,res)=>{const ip=req.ip,t=tries[ip]=(tries[ip]||[]).filter(x=>x>Date.now()-9e5);
  if(t.length>=10)return res.status(429).json({error:'Thử quá nhiều lần, vui lòng đợi 15 phút'});
  const r=await Q1('SELECT * FROM users WHERE username=? AND active=1',[String(req.body.u||'').trim().toLowerCase()]);
  if(!r.length||!checkPw(String(req.body.p||''),r[0].pass)){t.push(Date.now());return res.status(400).json({error:'Sai tên đăng nhập hoặc mật khẩu'})}
  res.setHeader('Set-Cookie',`sid=${sign({uid:Number(r[0].id),exp:Date.now()+30*864e5})}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000${req.secure?'; Secure':''}`);res.json({ok:1})}));
app.post('/api/logout',(q,r)=>{r.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/');r.json({ok:1})});
const auth=A(async(req,res,next)=>{const c=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid=')),p=c&&verify(c.slice(4));
  const r=p?await Q1('SELECT * FROM users WHERE id=? AND active=1',[p.uid]):[];
  if(!r.length)return res.status(401).json({error:'Chưa đăng nhập'});
  req.u={id:Number(r[0].id),username:r[0].username,name:r[0].name,role:r[0].role,class_id:r[0].class_id==null?null:Number(r[0].class_id)};next()});
const adm=(q,r,n)=>q.u.role!=='helper'?n():r.status(403).json({error:'Không có quyền'});
const sys=(q,r,n)=>q.u.role==='sysadmin'?n():r.status(403).json({error:'Chỉ sysadmin được thực hiện'});
async function ctx(req,res){const u=req.u,c=u.role==='sysadmin'?+req.query.c:u.class_id;
  if(!c){res.status(400).json({error:'Chưa chọn lớp'});return null}
  if(!(await Q1('SELECT id FROM classes WHERE id=?',[c])).length){res.status(404).json({error:'Không có lớp này'});return null}
  let y=String(req.query.y||'');if(!y)y=(await years(c))[0]||'';
  if(!y){res.status(404).json({error:'Lớp chưa có năm học'});return null}
  return{c,y}}
const view=(d,role)=>role!=='helper'?d:{...d,students:d.students.map(({id,saint,name,g})=>({id,saint,name,g}))};
const full=s=>s?(s.saint?s.saint+' ':'')+s.name:'?';
const LB={m:'Miệng',q:'15 phút',t:'Thi'},CL={P:'Có mặt',A:'Vắng có phép',U:'Vắng không phép','':'trống'};
const ROLES=['sysadmin','teacher','helper'];

app.get('/api/me',auth,A(async(q,r)=>{const u=q.u,cl=(await Q1('SELECT id,name FROM classes ORDER BY id')).map(x=>({id:Number(x.id),name:x.name}));
  r.json({me:{name:u.name,username:u.username,role:u.role==='helper'?'helper':'admin',kind:u.role,classId:u.class_id},classes:u.role==='sysadmin'?cl:cl.filter(x=>x.id===u.class_id),settings:await getSet()})}));
app.get('/api/data',auth,A(async(q,r)=>{const x=await ctx(q,r);if(!x)return;const d=await getDoc(x.c,x.y);
  if(!d)return r.status(404).json({error:'Không có dữ liệu năm học này'});
  r.json({years:await years(x.c),doc:{year:x.y,...view(d,q.u.role)}})}));
app.post('/api/op',auth,A((req,res)=>lock(async()=>{const x=await ctx(req,res);if(!x)return;const d=await getDoc(x.c,x.y);if(!d)return res.status(404).json({error:'Không có dữ liệu'});
  const L=[],ops=Array.isArray(req.body)?req.body.slice(0,200):[];
  for(const o of ops){const s=d.students.find(z=>z.id===o.id);
    if(o.t==='g'){if(!s||![1,2].includes(o.hk)||!LB[o.k])continue;const v=o.v===''?'':Math.min(10,Math.max(0,+o.v));if(v!==''&&isNaN(v))continue;
      s.g=s.g||{};s.g[o.hk]=s.g[o.hk]||{};const old=s.g[o.hk][o.k];if(old===v)continue;s.g[o.hk][o.k]=v;
      L.push(`Điểm ${LB[o.k]} HK${o.hk} của ${full(s)}: ${old===undefined||old===''?'trống':old} → ${v===''?'trống':v}`)}
    else if(o.t==='att'){if(!s||!/^\d{4}-\d\d-\d\d$/.test(o.day)||!['c','s','t'].includes(o.k))continue;
      if(o.k==='c'&&!(o.v in CL))continue;const v=o.k==='c'?o.v:!!o.v;
      const r=((d.att[o.day]=d.att[o.day]||{})[o.id]=d.att[o.day][o.id]||{}),old=r[o.k];if(old===v)continue;r[o.k]=v;
      const nm={c:'Học giáo lý',s:'Lễ Chúa nhật',t:'Lễ thứ Năm'}[o.k],f=z=>o.k==='c'?CL[z||'']:z?'có':'không';
      L.push(`Điểm danh ${o.day.split('-').reverse().join('/')} · ${nm} của ${full(s)}: ${f(old)} → ${f(v)}`)}
    else if(o.t==='delday'&&req.u.role!=='helper'&&d.att[o.day]){delete d.att[o.day];L.push('Xóa điểm danh ngày '+o.day)}}
  await save(x.c,x.y,d,req.u.name,L);res.json({ok:1})})));
const FL=['saint','name','dob','parish','father','fphone','mother','mphone','addr','note'];
app.post('/api/admin',auth,adm,A((req,res)=>lock(async()=>{const x=await ctx(req,res);if(!x)return;const d=await getDoc(x.c,x.y),b=req.body||{},old=new Map(d.students.map(s=>[s.id,s]));
  const key=a=>JSON.stringify(a.map(({g,...p})=>p));const before=key(d.students);
  d.students=(b.students||[]).slice(0,300).map(p=>{const o={id:String(p.id).slice(0,40)};FL.forEach(k=>o[k]=String(p[k]||'').slice(0,200));o.g=(old.get(o.id)||{}).g||{};return o});
  const ids=new Set(d.students.map(s=>s.id));Object.values(d.att).forEach(a=>Object.keys(a).forEach(i=>{if(!ids.has(i))delete a[i]}));
  await save(x.c,x.y,d,req.u.name,key(d.students)!==before?['Cập nhật hồ sơ thiếu nhi']:[]);res.json({doc:{year:x.y,...d}})})));
app.post('/api/year',auth,adm,A((req,res)=>lock(async()=>{const x=await ctx(req,res);if(!x)return;const name=String(req.body.name||'').trim().slice(0,20);
  if(!name)return res.status(400).json({error:'Nhập tên năm học'});if(await getDoc(x.c,name))return res.status(409).json({error:'Năm học này đã tồn tại'});
  const nd={students:[],att:{}};if(req.body.copy){const o=await getDoc(x.c,String(req.body.from||x.y));if(o)nd.students=o.students.map(s=>({...s,g:{}}))}
  await save(x.c,name,nd,req.u.name,['Tạo năm học '+name+(req.body.copy?' (sao chép danh sách thiếu nhi)':'')]);res.json({ok:1})})));
app.post('/api/restore',auth,adm,A((req,res)=>lock(async()=>{const x=await ctx(req,res);if(!x)return;const b=req.body;
  if(!b||!Array.isArray(b.students)||typeof b.att!=='object')return res.status(400).json({error:'File sao lưu không hợp lệ'});
  await save(x.c,x.y,{students:b.students,att:b.att},req.u.name,['Khôi phục dữ liệu từ file sao lưu']);res.json({ok:1})})));
app.get('/api/log',auth,adm,A(async(q,r)=>{const c=q.u.role==='sysadmin'?+q.query.c||null:q.u.class_id;
  const x=await Q1('SELECT ts,user,text,year FROM log WHERE class_id=?'+(q.u.role==='sysadmin'?' OR class_id IS NULL':'')+' ORDER BY id DESC LIMIT 300',[c]);
  r.json(x.map(w=>({ts:w.ts,user:w.user,text:w.text,year:w.year})))}));

/* --- Quản trị (sysadmin) --- */
app.post('/api/settings',auth,sys,A(async(req,res)=>{const s=(req.body||{}).set||{},n=(v,f)=>isFinite(+v)&&v!==''&&v!==null?+v:f;
  const set={w:[0,1,2].map(i=>n(s.w&&s.w[i],1)||1),A:n(s.A,8),B:n(s.B,6.5),C:n(s.C,5),min:n(s.min,5),mass:n(s.mass,80)};
  await db.execute({sql:"INSERT INTO kv(k,v) VALUES('settings',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",args:[JSON.stringify(set)]});
  await glog(req.u.name,'Cập nhật quy tắc tính điểm toàn hệ thống');res.json({set})}));
app.post('/api/classes',auth,sys,A(async(req,res)=>{const name=String(req.body.name||'').trim().slice(0,80),year=String(req.body.year||'').trim().slice(0,20);
  if(!name||!year)return res.status(400).json({error:'Nhập tên lớp và năm học đầu tiên'});
  const r=await db.execute({sql:'INSERT INTO classes(name) VALUES(?)',args:[name]}),cid=Number(r.lastInsertRowid);
  await save(cid,year,{students:[],att:{}},req.u.name,[`Tạo lớp "${name}", năm học ${year}`]);res.json({id:cid})}));
app.put('/api/classes/:id',auth,sys,A(async(req,res)=>{const name=String(req.body.name||'').trim().slice(0,80);if(!name)return res.status(400).json({error:'Nhập tên lớp'});
  await db.execute({sql:'UPDATE classes SET name=? WHERE id=?',args:[name,+req.params.id]});await glog(req.u.name,`Đổi tên lớp #${req.params.id} thành "${name}"`);res.json({ok:1})}));
app.get('/api/users',auth,sys,A(async(q,r)=>r.json((await Q1('SELECT id,username,name,role,class_id,active FROM users ORDER BY role,id')).map(u=>({id:Number(u.id),username:u.username,name:u.name,role:u.role,class_id:u.class_id==null?null:Number(u.class_id),active:Number(u.active)})))));
const teacherTaken=async(c,except)=>(await Q1("SELECT id FROM users WHERE role='teacher' AND active=1 AND class_id=? AND id<>?",[c,except||0])).length>0;
const classOk=async c=>(await Q1('SELECT id FROM classes WHERE id=?',[+c])).length>0;
app.post('/api/users',auth,sys,A((req,res)=>lock(async()=>{const b=req.body||{},username=String(b.username||'').trim().toLowerCase(),name=String(b.name||'').trim().slice(0,60),pw=String(b.password||''),role=b.role;
  if(!/^[a-z0-9._-]{3,30}$/.test(username))return res.status(400).json({error:'Tên đăng nhập 3-30 ký tự: chữ thường không dấu, số, . _ -'});
  if(!name)return res.status(400).json({error:'Nhập họ tên hiển thị'});if(pw.length<8)return res.status(400).json({error:'Mật khẩu tối thiểu 8 ký tự'});
  if(!ROLES.includes(role))return res.status(400).json({error:'Vai trò không hợp lệ'});
  let cid=null;if(role!=='sysadmin'){cid=+b.class_id;if(!await classOk(cid))return res.status(400).json({error:'Hãy chọn lớp'});
    if(role==='teacher'&&await teacherTaken(cid))return res.status(409).json({error:'Lớp này đã có giáo lý viên. Mỗi lớp chỉ có một giáo lý viên.'})}
  if((await Q1('SELECT id FROM users WHERE username=?',[username])).length)return res.status(409).json({error:'Tên đăng nhập đã tồn tại'});
  await db.execute({sql:'INSERT INTO users(username,name,role,class_id,pass) VALUES(?,?,?,?,?)',args:[username,name,role,cid,hashPw(pw)]});
  await glog(req.u.name,`Tạo tài khoản ${username} (${role})`);res.json({ok:1})})));
app.put('/api/users/:id',auth,sys,A((req,res)=>lock(async()=>{const id=+req.params.id,b=req.body||{},r=await Q1('SELECT * FROM users WHERE id=?',[id]);if(!r.length)return res.status(404).json({error:'Không có tài khoản'});
  const u=r[0];
  if('password'in b){if(String(b.password).length<8)return res.status(400).json({error:'Mật khẩu tối thiểu 8 ký tự'});await db.execute({sql:'UPDATE users SET pass=? WHERE id=?',args:[hashPw(String(b.password)),id]});await glog(req.u.name,`Đặt lại mật khẩu cho ${u.username}`)}
  if('active'in b){const a=b.active?1:0;if(id===req.u.id&&!a)return res.status(400).json({error:'Không thể tự khóa tài khoản của mình'});
    if(a&&u.role==='teacher'&&await teacherTaken(Number(u.class_id),id))return res.status(409).json({error:'Lớp này đã có giáo lý viên đang dùng'});
    await db.execute({sql:'UPDATE users SET active=? WHERE id=?',args:[a,id]});await glog(req.u.name,`${a?'Mở khóa':'Khóa'} tài khoản ${u.username}`)}
  if('name'in b&&String(b.name).trim())await db.execute({sql:'UPDATE users SET name=? WHERE id=?',args:[String(b.name).trim().slice(0,60),id]});
  res.json({ok:1})})));
app.use(express.static(__dirname+'/public'));
ready.then(()=>app.listen(E.PORT||3000,E.HOST||'0.0.0.0',()=>console.log('Chạy tại cổng '+(E.PORT||3000)))).catch(e=>{console.error('Lỗi khởi động:',e.message);process.exit(1)});