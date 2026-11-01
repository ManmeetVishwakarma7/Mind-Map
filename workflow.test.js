const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const temp=fs.mkdtempSync(path.join(os.tmpdir(),'mindmap-test-'));
const port=3000+Math.floor(Math.random()*20000);
let server,base,cookie,adminCookie;
function request(route,{method='GET',body,cookie:cookieOverride=cookie,contentType}={}){
 return new Promise((resolve,reject)=>{
  const data=body?(Buffer.isBuffer(body)?body:JSON.stringify(body)):undefined;
  const req=http.request(`${base}${route}`,{method,headers:{...(data?{'Content-Type':contentType||'application/json','Content-Length':Buffer.byteLength(data)}:{}),...(method!=='GET'?{'X-MindMap-Request':'1'}:{}),...(cookieOverride?{Cookie:cookieOverride}:{})}},res=>{
   let raw='';res.setEncoding('utf8');res.on('data',chunk=>raw+=chunk);res.on('end',()=>{const set=res.headers['set-cookie'];if(set?.length){if(route==='/api/auth/register')cookie=set[0].split(';')[0];if(route==='/api/auth/login')adminCookie=set[0].split(';')[0];}let parsed;try{parsed=JSON.parse(raw);}catch{parsed=raw;}resolve({status:res.statusCode,body:parsed,headers:res.headers});});
  });req.on('error',reject);if(data)req.write(data);req.end();
 });
}
function multipart(fields,file){const boundary='----MindMapTestBoundary';const chunks=[];for(const [name,value] of Object.entries(fields)){chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));}chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="sample.pdf"\r\nContent-Type: application/pdf\r\n\r\n`));chunks.push(file);chunks.push(Buffer.from(`\r\n--${boundary}--\r\n`));return {body:Buffer.concat(chunks),contentType:`multipart/form-data; boundary=${boundary}`};}

test('student workflow filters No coverage and protects admin routes',async(t)=>{
 const dbPath=path.join(temp,'mindmap.db');
 server=spawn(process.execPath,['src/server.js'],{cwd:path.resolve(__dirname,'..'),env:{...process.env,PORT:String(port),DB_PATH:dbPath,SESSION_SECRET:'test-secret-that-is-at-least-32-characters-long',ADMIN_EMAIL:'admin@test.example',ADMIN_PASSWORD:'admin-password-12345',UPLOAD_DIR:path.join(temp,'uploads'),NODE_ENV:'test'},stdio:['ignore','pipe','pipe']});
 let startup='';server.stdout.on('data',d=>startup+=d);server.stderr.on('data',d=>startup+=d);base=`http://127.0.0.1:${port}`;
 t.after(async()=>{if(server&&server.exitCode===null){server.kill();await new Promise(resolve=>{const timer=setTimeout(resolve,1500);server.once('exit',()=>{clearTimeout(timer);resolve();});});}try{fs.rmSync(temp,{recursive:true,force:true,maxRetries:5,retryDelay:200});}catch{}});
 for(let i=0;i<60;i++){if(startup.includes('MindMap running'))break;if(server.exitCode!==null)throw new Error(startup);await new Promise(r=>setTimeout(r,250));}
 assert.match(startup,/MindMap running/);
 const reg=await request('/api/auth/register',{method:'POST',body:{name:'Test Student',email:'student@example.test',password:'password-12345'}});
 assert.equal(reg.status,201);assert.equal(reg.body.user.role,'student');
 const subjects=(await request('/api/subjects')).body;assert.equal(subjects.length,6);
 const ds=subjects.find(x=>x.code==='BCS301');const subject=await request(`/api/subjects/${ds.id}`);const unitId=subject.body.units[0].id;
 const topics=(await request(`/api/units/${unitId}/topics`)).body.topics;assert.ok(topics.length>=2);
 const first=topics[0],second=topics[1];
 assert.equal((await request(`/api/coverage/${first.topic_id}`,{method:'PUT',body:{studied:true,note:'Reviewed'}})).status,200);
 assert.equal((await request(`/api/coverage/${second.topic_id}`,{method:'PUT',body:{studied:false,note:'Not yet'}})).status,200);
 const tampered=await request('/api/assessments',{method:'POST',body:{subjectId:ds.id,unitId,topicIds:[second.topic_id],count:1}});assert.equal(tampered.status,422,'the server rechecks selected topic coverage');
 const insertQuestion=(topic,text,answer)=>{
  const db=require('better-sqlite3')(dbPath);const row=db.prepare('SELECT u.subject_id,u.id AS unit_id FROM topics t JOIN units u ON u.id=t.unit_id WHERE t.id=?').get(topic.topic_id);
  const info=db.prepare(`INSERT INTO questions(subject_id,unit_id,topic_id,text,type,options,correct_answer,explanation,difficulty,marks) VALUES(?,?,?,?,'mcq','["A","B"]',?,'Test explanation','easy',1)`).run(row.subject_id,row.unit_id,topic.topic_id,text,answer);db.close();return info.lastInsertRowid;
 };
 insertQuestion(first,'Question for studied topic?','A');const excluded=insertQuestion(second,'Question for not studied topic?','B');
 const assessment=await request('/api/assessments',{method:'POST',body:{subjectId:ds.id,unitId,count:10}});
 assert.equal(assessment.status,201);assert.equal(assessment.body.questions.length,1);assert.notEqual(assessment.body.questions[0].id,excluded);assert.equal(assessment.body.questions[0].topic,first.topic_title);
 const submitted=await request(`/api/assessments/${assessment.body.id}/submit`,{method:'POST',body:{answers:{[assessment.body.questions[0].id]:'A'}}});
 assert.equal(submitted.status,200);assert.equal(submitted.body.assessment.accuracy,100);assert.equal(submitted.body.assessment.earned,1);assert.equal(submitted.body.assessment.attemptedCount,1);assert.equal(submitted.body.assessment.unansweredCount,0);assert.equal(submitted.body.topicSummary[0].accuracy,100);
 const analytics=(await request('/api/analytics')).body;const noTopic=analytics.topics.find(x=>x.id===second.topic_id);assert.equal(noTopic.status,'not_studied');assert.equal(noTopic.accuracy,0);
 assert.equal((await request('/api/admin/stats')).status,403);
 const draft=await request('/api/admin/resources',{method:'POST',body:{topic_id:first.topic_id,title:'Draft resource',kind:'notes',resource_type:'notes',url:'https://example.test/notes',description:'Draft only',publication_status:'draft',visibility:'published',tags:[]},cookie:cookie});
 assert.equal(draft.status,403,'students cannot manage resource content');
 assert.equal((await request('/api/admin/resources/upload',{method:'POST',body:Buffer.from('not multipart'),contentType:'text/plain',cookie})).status,403,'student upload access is forbidden before body parsing');
 assert.equal((await request('/api/assessments')).body.length,1);
 const studentCookie=cookie;
 const adminLogin=await request('/api/auth/login',{method:'POST',body:{email:'admin@test.example',password:'admin-password-12345'},cookie:''});
 assert.equal(adminLogin.status,200);assert.equal(adminLogin.body.user.role,'admin');
 assert.equal((await request('/api/admin/stats',{cookie:adminCookie})).status,200);
 const up=multipart({topic_id:first.topic_id,title:'Test PDF',description:'Private test upload',resource_type:'pdf',visibility:'published',publication_status:'draft',tags:'test,upload'},Buffer.from('%PDF-1.4\n test document'));
 const uploaded=await request('/api/admin/resources/upload',{method:'POST',body:up.body,contentType:up.contentType,cookie:adminCookie});assert.equal(uploaded.status,201,JSON.stringify(uploaded.body));
 const publishedStudentResources=await request(`/api/resources?topicId=${first.topic_id}`,{cookie:studentCookie});assert.equal(publishedStudentResources.body.some(r=>r.id===uploaded.body.id),false,'draft resources stay hidden');
 const publish=await request(`/api/admin/resources/${uploaded.body.id}`,{method:'PUT',cookie:adminCookie,body:{topic_id:first.topic_id,title:'Test PDF',kind:'notes',resource_type:'pdf',url:uploaded.body.url,description:'Published test upload',verified:true,visibility:'published',publication_status:'published',tags:['test','upload']}});assert.equal(publish.status,200,JSON.stringify(publish.body));
 const visible=await request(`/api/resources?topicId=${first.topic_id}`,{cookie:studentCookie});assert.ok(visible.body.some(r=>r.id===uploaded.body.id));
 const fileResponse=await request(uploaded.body.url,{cookie:studentCookie});assert.equal(fileResponse.status,200);assert.match(fileResponse.headers['content-type'],/application\/pdf/);
 assert.equal((await request(uploaded.body.url,{cookie:'connect.sid=invalid'})).status,401);
 const fake=multipart({topic_id:first.topic_id,title:'Fake PDF',resource_type:'pdf',visibility:'published',publication_status:'draft'},Buffer.from('not actually a PDF'));
 assert.equal((await request('/api/admin/resources/upload',{method:'POST',body:fake.body,contentType:fake.contentType,cookie:adminCookie})).status,400,'file signatures are checked, not only names and MIME');
});

test('file validation rejects executable and mismatched MIME types',()=>{
 const {safeKey}=require('../src/storage');
 assert.throws(()=>safeKey('payload.exe','application/octet-stream',10),/not supported/);
 assert.throws(()=>safeKey('notes.pdf','text/plain',10),/MIME type/);
 assert.throws(()=>safeKey('large.pdf','application/pdf',30*1024*1024),/smaller than/);
 assert.throws(()=>require('../src/storage').validateSignature('pdf',Buffer.from('not a PDF')),/does not match/);
});
