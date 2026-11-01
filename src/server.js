const path = require('node:path');
try { process.loadEnvFile(path.resolve(__dirname, '..', '.env')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const crypto = require('node:crypto');
const { db, initDb, seedSyllabus } = require('./db');
const { buildGuidance, scoreAnswers } = require('./engine');
const { safeKey, validateSignature, saveBuffer, deleteKey, getBuffer, getMaxBytes } = require('./storage');

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET || 'local-development-secret-change-before-publishing-2026';
if(process.env.NODE_ENV==='production'&&(!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32)){throw new Error('Production startup requires SESSION_SECRET with at least 32 characters.');}

class PostgresSessionStore extends session.Store {
  get(sid, callback) {
    db.pool.query('SELECT sess FROM mindmap_sessions WHERE sid=$1 AND expire>CURRENT_TIMESTAMP', [sid])
      .then(result => callback(null, result.rows[0]?.sess || null)).catch(callback);
  }
  set(sid, sess, callback = () => {}) {
    const expires = sess.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + 7 * 86400000);
    db.pool.query(`INSERT INTO mindmap_sessions(sid,sess,expire) VALUES($1,$2,$3) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess,expire=excluded.expire`, [sid, JSON.stringify(sess), expires])
      .then(() => callback(null)).catch(callback);
  }
  destroy(sid, callback = () => {}) {
    db.pool.query('DELETE FROM mindmap_sessions WHERE sid=$1', [sid]).then(() => callback(null)).catch(callback);
  }
  touch(sid, sess, callback = () => {}) { this.set(sid, sess, callback); }
}

app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], connectSrc: ["'self'"], imgSrc: ["'self'", 'data:'] } } }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(session({
  store: new PostgresSessionStore(),
  secret: sessionSecret, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use((req,res,next)=>{if(['GET','HEAD','OPTIONS'].includes(req.method)||req.path==='/api/health'||req.path==='/api/session')return next();const origin=req.get('origin');if(origin&&origin!==`${req.protocol}://${req.get('host')}`)return res.status(403).json({error:'Request origin could not be verified.'});if(req.path.startsWith('/api/')&&!req.path.startsWith('/api/auth/')&&req.get('x-mindmap-request')!=='1')return res.status(403).json({error:'Request verification failed.'});next();});
app.use(express.static(path.join(__dirname, '..', 'public'), { etag: true, maxAge: '1h' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many sign-in attempts. Please try again in 15 minutes.' } });
const registerSchema = z.object({ name: z.string().trim().min(2).max(80), email: z.string().trim().email().max(254), password: z.string().min(10).max(200) });
const loginSchema = z.object({ email: z.string().trim().email(), password: z.string().min(1).max(200) });
const requireAuth = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'Please sign in to continue.' });
const userDTO = (user) => ({ id: user.id, name: user.name, email: user.email, role: user.role });
const requireAdmin = async (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in to continue.' });
  const user = await db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.user.id);
  if (!user || user.role !== 'admin') {
    if (user) req.session.user = userDTO(user);
    return res.status(403).json({ error: 'Administrator access is required.' });
  }
  req.session.user = userDTO(user);
  next();
};
const validationError = (error) => error?.issues?.map((i) => i.message).join(' ') || 'Invalid request.';

app.get('/api/health', async (_req, res) => { try { await db.pool.query('SELECT 1'); res.json({ status: 'ok', app: 'MindMap', database: 'connected' }); } catch { res.status(503).json({ status: 'unavailable', app: 'MindMap', database: 'disconnected' }); } });
app.get('/api/session', async (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  const user = await db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.user.id);
  if (!user) { req.session.destroy(() => {}); return res.json({ user: null }); }
  req.session.user = userDTO(user);
  res.json({ user: req.session.user });
});
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: validationError(parsed.error) });
  try {
    const hash = await bcrypt.hash(parsed.data.password, 12);
    const info = await db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)').run(parsed.data.name, parsed.data.email.toLowerCase(), hash);
    const user = userDTO(await db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid));
    req.session.regenerate((err) => err ? res.status(500).json({ error: 'Could not create a secure session.' }) : (req.session.user = user, res.status(201).json({ user })));
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    res.status(500).json({ error: 'Account creation failed.' });
  }
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: validationError(parsed.error) });
  const user = await db.prepare('SELECT * FROM users WHERE email=?').get(parsed.data.email.toLowerCase());
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  req.session.regenerate((err) => err ? res.status(500).json({ error: 'Could not create a secure session.' }) : (req.session.user = userDTO(user), res.json({ user: req.session.user })));
});
app.post('/api/auth/logout', requireAuth, (req, res) => req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({ ok: true }); }));
app.get('/api/profile', requireAuth, async (req, res) => {const createdAt=(await db.prepare('SELECT created_at FROM users WHERE id=?').get(req.session.user.id)).created_at;const progress=await db.prepare('SELECT COUNT(t.id) AS total,COALESCE(SUM(CASE WHEN c.studied=1 THEN 1 ELSE 0 END),0) AS studied FROM topics t LEFT JOIN coverage c ON c.topic_id=t.id AND c.user_id=?').get(req.session.user.id);res.json({user:req.session.user,createdAt,progress});});
app.patch('/api/profile', requireAuth, async (req, res) => {
  const parsed = z.object({ name: z.string().trim().min(2).max(80) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: validationError(parsed.error) });
  await db.prepare('UPDATE users SET name=? WHERE id=?').run(parsed.data.name, req.session.user.id);
  req.session.user.name = parsed.data.name; res.json({ user: req.session.user });
});

const topicQuery = `SELECT t.id AS topic_id,t.title AS topic_title,t.position,u.id AS unit_id,u.number AS unit_number,u.title AS unit_title,s.id AS subject_id,s.code,s.name AS subject_name,s.semester,
 co.studied,COALESCE(co.note,'') AS note,co.updated_at,
 (SELECT COUNT(*) FROM answers a JOIN questions q ON q.id=a.question_id JOIN assessments ass ON ass.id=a.assessment_id WHERE ass.user_id=? AND ass.completed_at IS NOT NULL AND q.topic_id=t.id) AS attempts,
 (SELECT COALESCE(100.0*SUM(a.earned)/NULLIF(SUM(q.marks),0),0) FROM answers a JOIN questions q ON q.id=a.question_id JOIN assessments ass ON ass.id=a.assessment_id WHERE ass.user_id=? AND ass.completed_at IS NOT NULL AND q.topic_id=t.id) AS accuracy
 FROM topics t JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id LEFT JOIN coverage co ON co.topic_id=t.id AND co.user_id=?`;
app.get('/api/subjects', requireAuth, async (_req, res) => res.json(await db.prepare(`SELECT s.id,s.code,s.name,s.semester,COUNT(DISTINCT u.id) AS units,COUNT(t.id) AS topics FROM subjects s LEFT JOIN units u ON u.subject_id=s.id LEFT JOIN topics t ON t.unit_id=u.id GROUP BY s.id,s.code,s.name,s.semester ORDER BY s.semester,s.code`).all()));
app.get('/api/subjects/:id', requireAuth, async (req, res) => {
  const subject = await db.prepare('SELECT * FROM subjects WHERE id=?').get(Number(req.params.id));
  if (!subject) return res.status(404).json({ error: 'Subject not found.' });
  const units = await db.prepare(`SELECT u.id,u.number,u.title,COUNT(t.id) AS topic_count FROM units u LEFT JOIN topics t ON t.unit_id=u.id WHERE u.subject_id=? GROUP BY u.id ORDER BY u.number`).all(subject.id);
  res.json({ ...subject, units });
});
app.get('/api/units/:id/topics', requireAuth, async (req, res) => {
  const uid = Number(req.params.id);
  const unit = await db.prepare('SELECT u.*,s.id AS subject_id,s.code,s.name AS subject_name FROM units u JOIN subjects s ON s.id=u.subject_id WHERE u.id=?').get(uid);
  if (!unit) return res.status(404).json({ error: 'Unit not found.' });
  const topics = await db.prepare(`${topicQuery} WHERE u.id=? ORDER BY t.position,t.id`).all(req.session.user.id,req.session.user.id,req.session.user.id,uid);
  res.json({ unit, topics });
});
app.put('/api/coverage/:topicId', requireAuth, async (req, res) => {
  const parsed = z.object({ studied: z.boolean(), note: z.string().trim().max(300).default('') }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: validationError(parsed.error) });
  const topicId = Number(req.params.topicId);
  if (!await db.prepare('SELECT 1 FROM topics WHERE id=?').get(topicId)) return res.status(404).json({ error: 'Topic not found.' });
  await db.transaction(async () => {
    await db.prepare(`INSERT INTO coverage(user_id,topic_id,studied,note,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,topic_id) DO UPDATE SET studied=excluded.studied,note=excluded.note,updated_at=CURRENT_TIMESTAMP`).run(req.session.user.id,topicId,+parsed.data.studied,parsed.data.note);
    await db.prepare('INSERT INTO coverage_history(user_id,topic_id,studied,note) VALUES(?,?,?,?)').run(req.session.user.id,topicId,+parsed.data.studied,parsed.data.note);
  }); res.json({ ok: true });
});
app.get('/api/coverage/history', requireAuth, async (req,res) => res.json(await db.prepare(`SELECT h.*,t.title AS topic_title,s.code,s.name AS subject_name FROM coverage_history h JOIN topics t ON t.id=h.topic_id JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id WHERE h.user_id=? ORDER BY h.changed_at DESC LIMIT 100`).all(req.session.user.id)));

app.get('/api/dashboard', requireAuth, async (req, res) => {
  const uid=req.session.user.id;
  const overall=await db.prepare(`SELECT COUNT(*) AS topics, SUM(CASE WHEN co.studied=1 THEN 1 ELSE 0 END) AS studied, SUM(CASE WHEN co.studied=0 THEN 1 ELSE 0 END) AS not_studied FROM topics t LEFT JOIN coverage co ON co.topic_id=t.id AND co.user_id=?`).get(uid);
  const totals=await db.prepare('SELECT COUNT(*) AS assessments,COALESCE(AVG(accuracy),0) AS accuracy FROM assessments WHERE user_id=? AND completed_at IS NOT NULL').get(uid);
  const recent=await db.prepare(`SELECT a.*,s.code,s.name AS subject_name FROM assessments a JOIN subjects s ON s.id=a.subject_id WHERE a.user_id=? AND a.completed_at IS NOT NULL ORDER BY a.completed_at DESC LIMIT 5`).all(uid);
  const weakTopics=await db.prepare(`SELECT t.id,t.title,s.code,COALESCE(100.0*SUM(a.earned)/NULLIF(SUM(q.marks),0),0) accuracy FROM coverage c JOIN topics t ON t.id=c.topic_id JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id JOIN questions q ON q.topic_id=t.id JOIN answers a ON a.question_id=q.id JOIN assessments ass ON ass.id=a.assessment_id AND ass.user_id=c.user_id AND ass.completed_at IS NOT NULL WHERE c.user_id=? AND c.studied=1 GROUP BY t.id HAVING COUNT(a.question_id)>0 ORDER BY accuracy LIMIT 4`).all(uid);
  const recentResources=await db.prepare(`SELECT r.*,t.title AS topic_title,s.code,u.number AS unit_number FROM resources r JOIN topics t ON t.id=r.topic_id JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id WHERE COALESCE(r.publication_status,'published')='published' AND COALESCE(r.visibility,'published')='published' ORDER BY r.created_at DESC LIMIT 4`).all();
  const subjects=await db.prepare(`SELECT s.id,s.code,s.name,s.semester,COUNT(t.id) AS topic_count,SUM(CASE WHEN co.studied=1 THEN 1 ELSE 0 END) AS studied,COALESCE((SELECT AVG(a.accuracy) FROM assessments a WHERE a.subject_id=s.id AND a.user_id=? AND a.completed_at IS NOT NULL),0) AS accuracy FROM subjects s JOIN units u ON u.subject_id=s.id JOIN topics t ON t.unit_id=u.id LEFT JOIN coverage co ON co.topic_id=t.id AND co.user_id=? GROUP BY s.id,s.code,s.name,s.semester ORDER BY s.semester,s.code`).all(uid,uid);
  const improvement=recent.length>1?Number((recent[0].accuracy-recent[1].accuracy).toFixed(1)):null;
  res.json({ overall, totals, recent, subjects,weakTopics,recentResources,improvement });
});

app.get('/api/analytics', requireAuth, async (req, res) => {
  const uid=req.session.user.id;
  const rows=await db.prepare(`${topicQuery} ORDER BY s.semester,s.code,u.number,t.position`).all(uid,uid,uid);
  const guidance=buildGuidance(rows.map(r=>({id:r.topic_id,topic:r.topic_title,subject:r.subject_name,subjectCode:r.code,unit:r.unit_number,unitTitle:r.unit_title,studied:r.studied===1,attempts:r.attempts,accuracy:r.accuracy})));
  const history=await db.prepare(`SELECT a.id,a.started_at,a.completed_at,a.accuracy,a.earned,a.possible,a.question_count,a.attempted_count,a.correct_count,a.incorrect_count,a.unanswered_count,s.code,s.name AS subject_name FROM assessments a JOIN subjects s ON s.id=a.subject_id WHERE a.user_id=? AND a.completed_at IS NOT NULL ORDER BY a.completed_at`).all(uid);
  const subjects=await db.prepare(`SELECT s.id,s.code,s.name,COALESCE(AVG(a.accuracy),0) AS accuracy,COUNT(a.id) AS assessments FROM subjects s LEFT JOIN assessments a ON a.subject_id=s.id AND a.user_id=? AND a.completed_at IS NOT NULL GROUP BY s.id,s.code,s.name,s.semester ORDER BY s.semester,s.code`).all(uid);
  const units=await db.prepare(`SELECT u.id,u.number,u.title,s.code,s.name AS subject_name,COALESCE(AVG(a.accuracy),0) AS accuracy,COUNT(DISTINCT a.id) AS assessments FROM units u JOIN subjects s ON s.id=u.subject_id LEFT JOIN topics t ON t.unit_id=u.id LEFT JOIN questions q ON q.topic_id=t.id LEFT JOIN answers an ON an.question_id=q.id LEFT JOIN assessments a ON a.id=an.assessment_id AND a.user_id=? AND a.completed_at IS NOT NULL GROUP BY u.id,u.number,u.title,s.code,s.name,s.semester ORDER BY s.semester,s.code,u.number`).all(uid);
  const improvement=history.length>1?Number((history.at(-1).accuracy-history.at(-2).accuracy).toFixed(1)):null;
  res.json({ topics:guidance.map(x=>({...x,priority:x.status==='needs_improvement'?(x.accuracy<30?'high':'medium'):x.status==='moderate'?'medium':x.status==='not_studied'?'study_next':x.status==='not_assessed'?'assess':'maintain'})),history,subjects,units,overall:history.length?Number((history.reduce((n,x)=>n+x.accuracy,0)/history.length).toFixed(1)):null,improvement });
});
app.get('/api/recommendations', requireAuth, async (req,res) => {
  const rows=await db.prepare(`${topicQuery} ORDER BY s.semester,s.code,u.number,t.position`).all(req.session.user.id,req.session.user.id,req.session.user.id);
  const guidance=buildGuidance(rows.map(r=>({id:r.topic_id,topic:r.topic_title,subject:r.subject_name,subjectCode:r.code,unit:r.unit_number,unitTitle:r.unit_title,studied:r.studied===1,attempts:r.attempts,accuracy:r.accuracy})));
  res.json(guidance.filter(x=>x.status!=='strong').map(x=>({...x,priority:x.status==='needs_improvement'?(x.accuracy<30?'high':'medium'):x.status==='moderate'?'medium':x.status==='not_studied'?'study_next':'assess'})));
});
app.get('/api/assessments', requireAuth, async (req,res) => {const p=z.object({subject:z.string().optional(),from:z.string().optional(),to:z.string().optional()}).safeParse(req.query);if(!p.success)return res.status(400).json({error:validationError(p.error)});let sql=`SELECT a.*,s.code,s.name AS subject_name FROM assessments a JOIN subjects s ON s.id=a.subject_id WHERE a.user_id=? AND a.completed_at IS NOT NULL`;const args=[req.session.user.id];if(p.data.subject){sql+=' AND s.code=?';args.push(p.data.subject);}if(p.data.from){sql+=' AND a.completed_at::date>=?::date';args.push(p.data.from);}if(p.data.to){sql+=' AND a.completed_at::date<=?::date';args.push(p.data.to);}sql+=' ORDER BY a.completed_at DESC';res.json(await db.prepare(sql).all(...args));});
app.post('/api/assessments', requireAuth, async (req,res) => {
  const parsed=z.object({subjectId:z.number().int().positive(),unitId:z.number().int().positive().optional(),topicIds:z.array(z.number().int().positive()).max(213).optional(),count:z.number().int().min(1).max(30).default(10),difficulty:z.enum(['any','easy','medium','hard']).default('any')}).safeParse(req.body);
  if(!parsed.success)return res.status(400).json({error:validationError(parsed.error)});
  const {subjectId,unitId,count,difficulty}=parsed.data;
  const subject=await db.prepare('SELECT * FROM subjects WHERE id=?').get(subjectId); if(!subject)return res.status(404).json({error:'Subject not found.'});
  const params=[req.session.user.id,subjectId]; let extra='';
  if(unitId){extra+=' AND u.id=?';params.push(unitId);}
  if(parsed.data.topicIds?.length){extra+=` AND q.topic_id IN (${parsed.data.topicIds.map(()=>'?').join(',')})`;params.push(...parsed.data.topicIds);}
  if(parsed.data.topicIds&&!parsed.data.topicIds.length)return res.status(422).json({error:'Select at least one topic you have marked studied.'});
  if(parsed.data.topicIds?.length){const eligible=await db.prepare(`SELECT COUNT(*) n FROM topics t JOIN units u ON u.id=t.unit_id JOIN coverage c ON c.topic_id=t.id AND c.user_id=? AND c.studied=1 WHERE u.subject_id=? AND t.id IN (${parsed.data.topicIds.map(()=>'?').join(',')})${unitId?' AND u.id=?':''}`).get(req.session.user.id,subjectId,...parsed.data.topicIds,...(unitId?[unitId]:[]));if(eligible.n!==parsed.data.topicIds.length)return res.status(422).json({error:'One or more selected topics are not marked studied for this subject/unit.'});}
  if(difficulty!=='any'){extra+=' AND q.difficulty=?';params.push(difficulty);}
  const pool=await db.prepare(`SELECT q.*,t.title AS topic_title,u.number AS unit_number FROM questions q JOIN topics t ON t.id=q.topic_id JOIN units u ON u.id=q.unit_id JOIN coverage c ON c.topic_id=t.id AND c.user_id=? AND c.studied=1 WHERE q.subject_id=?${extra} ORDER BY RANDOM()`).all(...params);
  if(!pool.length)return res.status(422).json({error:'No question-bank items match your studied topics and filters. Update coverage or ask an administrator to add questions for these topics.'});
  const selected=pool.slice(0,count);
  const info=await db.prepare('INSERT INTO assessments(user_id,subject_id,question_count) VALUES(?,?,?)').run(req.session.user.id,subjectId,selected.length);
  for (const [i,q] of selected.entries()) await db.prepare('INSERT INTO assessment_questions(assessment_id,question_id,position) VALUES(?,?,?)').run(info.lastInsertRowid,q.id,i);
  res.status(201).json({id:info.lastInsertRowid,subject,questions:selected.map(({id,text,type,options,marks,topic_title,unit_number})=>({id,text,type,options:JSON.parse(options),marks,topic:topic_title,unit:unit_number}))});
});
app.post('/api/assessments/:id/review',requireAuth,async (req,res)=>{const aid=Number(req.params.id);const assessment=await db.prepare('SELECT * FROM assessments WHERE id=? AND user_id=? AND completed_at IS NULL').get(aid,req.session.user.id);if(!assessment)return res.status(404).json({error:'Active assessment not found.'});const p=z.object({questionId:z.number().int().positive(),marked:z.boolean()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});const info=await db.prepare('UPDATE assessment_questions SET marked_for_review=? WHERE assessment_id=? AND question_id=?').run(+p.data.marked,aid,p.data.questionId);if(!info.changes)return res.status(404).json({error:'Question is not part of this assessment.'});res.json({ok:true});});
app.post('/api/assessments/:id/submit', requireAuth, async (req,res) => {
  const aid=Number(req.params.id); const assessment=await db.prepare('SELECT * FROM assessments WHERE id=? AND user_id=?').get(aid,req.session.user.id);
  if(!assessment)return res.status(404).json({error:'Assessment not found.'}); if(assessment.completed_at)return res.status(409).json({error:'This assessment has already been submitted.'});
  const parsed=z.object({answers:z.record(z.string(),z.union([z.string().max(5000),z.array(z.string().max(200)),z.null()]))}).safeParse(req.body);
  if(!parsed.success)return res.status(400).json({error:validationError(parsed.error)});
  const questions=await db.prepare(`SELECT q.* FROM assessment_questions aq JOIN questions q ON q.id=aq.question_id WHERE aq.assessment_id=? ORDER BY aq.position`).all(aid);
  const answers=Object.fromEntries(Object.entries(parsed.data.answers).map(([id,value])=>[id,Array.isArray(value)?value:value]));
  const result=scoreAnswers(questions,answers);
  const attemptedCount=result.graded.filter(x=>x.answer!==null&&x.answer!==undefined&&String(Array.isArray(x.answer)?x.answer.join(''):x.answer).trim()!=='').length;
  const incorrectCount=result.graded.filter(x=>x.answer!==null&&x.answer!==undefined&&String(Array.isArray(x.answer)?x.answer.join(''):x.answer).trim()!==''&&!x.correct).length;
  const topicResults=new Map();for(const question of questions){const item=topicResults.get(question.topic_id)||{topic_id:question.topic_id,question_count:0,attempted_count:0,correct_count:0,earned:0,possible:0};const grade=result.graded.find(g=>g.question_id===question.id);item.question_count++;item.possible+=question.marks;if(grade.answer!==null&&grade.answer!==undefined&&String(Array.isArray(grade.answer)?grade.answer.join(''):grade.answer).trim()!=='')item.attempted_count++;if(grade.correct)item.correct_count++;item.earned+=grade.earned;topicResults.set(question.topic_id,item);}
  await db.transaction(async ()=>{
    for(const graded of result.graded) await db.prepare('INSERT INTO answers(assessment_id,question_id,answer,correct,earned) VALUES(?,?,?,?,?)').run(aid,graded.question_id,Array.isArray(graded.answer)?JSON.stringify(graded.answer):graded.answer,+graded.correct,graded.earned);
    await db.prepare('UPDATE assessments SET completed_at=CURRENT_TIMESTAMP,earned=?,possible=?,accuracy=?,attempted_count=?,correct_count=?,incorrect_count=?,unanswered_count=? WHERE id=?').run(result.earned,result.possible,result.accuracy,attemptedCount,result.correctCount,incorrectCount,questions.length-attemptedCount,aid);
    for(const item of topicResults.values()) await db.prepare('INSERT INTO assessment_topic_results(assessment_id,topic_id,question_count,attempted_count,correct_count,earned,possible,accuracy) VALUES(?,?,?,?,?,?,?,?)').run(aid,item.topic_id,item.question_count,item.attempted_count,item.correct_count,item.earned,item.possible,item.possible?item.earned/item.possible*100:0);
    const topics=[...new Set(questions.map(q=>q.topic_id))];
    for(const topicId of topics){
      const row=await db.prepare(`SELECT COUNT(*) AS attempts,COALESCE(100.0*SUM(a.earned)/NULLIF(SUM(q.marks),0),0) AS accuracy FROM answers a JOIN questions q ON q.id=a.question_id JOIN assessments ass ON ass.id=a.assessment_id WHERE ass.user_id=? AND ass.completed_at IS NOT NULL AND q.topic_id=?`).get(req.session.user.id,topicId);
      if(Number(row.accuracy)<80) await db.prepare('INSERT INTO recommendations(user_id,topic_id,reason) VALUES(?,?,?)').run(req.session.user.id,topicId,`Assessment accuracy is ${Math.round(row.accuracy)}% across ${row.attempts} question(s).`);
    }
  });
  const detailed=(await db.prepare(`SELECT q.id,q.text,q.explanation,q.correct_answer,q.type,q.options,a.answer,a.correct,a.earned,q.marks,t.title AS topic FROM answers a JOIN questions q ON q.id=a.question_id JOIN topics t ON t.id=q.topic_id WHERE a.assessment_id=? ORDER BY q.id`).all(aid)).map(r=>({...r,options:JSON.parse(r.options),answer:r.type==='multiple_select'&&r.answer?JSON.parse(r.answer):r.answer}));
  const topicSummary=await Promise.all([...topicResults.values()].map(async x=>({...x,topic:(await db.prepare('SELECT title FROM topics WHERE id=?').get(x.topic_id)).title,accuracy:x.possible?x.earned/x.possible*100:0,status:x.possible&&x.earned/x.possible>=.8?'strong':x.possible&&x.earned/x.possible>=.5?'moderate':x.possible?'needs_improvement':'not_assessed'})));
  res.json({assessment:{id:aid,...result,attemptedCount,incorrectCount,unansweredCount:questions.length-attemptedCount,accuracy:result.accuracy},topicSummary,questions:detailed});
});
app.get('/api/assessments/:id',requireAuth,async (req,res)=>{
 const row=await db.prepare('SELECT a.*,s.code,s.name AS subject_name FROM assessments a JOIN subjects s ON s.id=a.subject_id WHERE a.id=? AND a.user_id=? AND a.completed_at IS NOT NULL').get(Number(req.params.id),req.session.user.id);
 if(!row)return res.status(404).json({error:'Completed assessment not found.'});
 const questions=(await db.prepare(`SELECT q.text,q.explanation,q.correct_answer,q.options,q.type,a.answer,a.correct,a.earned,q.marks,t.title AS topic FROM answers a JOIN questions q ON q.id=a.question_id JOIN topics t ON t.id=q.topic_id WHERE a.assessment_id=? ORDER BY q.id`).all(row.id)).map(r=>({...r,options:JSON.parse(r.options),answer:r.type==='multiple_select'&&r.answer?JSON.parse(r.answer):r.answer,correct_answer:r.type==='multiple_select'?JSON.parse(r.correct_answer):r.correct_answer}));const topicSummary=await db.prepare('SELECT tr.*,t.title AS topic FROM assessment_topic_results tr JOIN topics t ON t.id=tr.topic_id WHERE assessment_id=?').all(row.id);res.json({assessment:row,topicSummary,questions});
});
const resourceSelect=`SELECT r.*,t.title AS topic_title,u.number AS unit_number,s.code,s.name AS subject_name FROM resources r JOIN topics t ON t.id=r.topic_id JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id`;
app.get('/api/resources',requireAuth,async (req,res)=>{
 const p=z.object({topicId:z.coerce.number().int().positive().optional(),subjectId:z.coerce.number().int().positive().optional(),unitId:z.coerce.number().int().positive().optional(),kind:z.string().optional(),q:z.string().max(120).optional(),all:z.enum(['0','1']).optional()}).safeParse(req.query);if(!p.success)return res.status(400).json({error:validationError(p.error)});
 const admin=req.session.user.role==='admin'&&p.data.all==='1';let sql=resourceSelect;const where=[],params=[];if(!admin)where.push("r.visibility='published' AND r.publication_status='published'");if(p.data.topicId){where.push('t.id=?');params.push(p.data.topicId);}if(p.data.subjectId){where.push('s.id=?');params.push(p.data.subjectId);}if(p.data.unitId){where.push('u.id=?');params.push(p.data.unitId);}if(p.data.kind){where.push('(r.resource_type=? OR r.kind=?)');params.push(p.data.kind,p.data.kind);}if(p.data.q){where.push('(r.title ILIKE ? OR r.description ILIKE ? OR r.tags ILIKE ? OR t.title ILIKE ?)');const q=`%${p.data.q}%`;params.push(q,q,q,q);}if(where.length)sql+=` WHERE ${where.join(' AND ')}`;sql+=' ORDER BY s.semester,s.code,u.number,t.position,r.created_at DESC';res.json(await db.prepare(sql).all(...params));
});
app.get('/api/resources/:id/file',requireAuth,async (req,res)=>{const resource=await db.prepare('SELECT * FROM resources WHERE id=?').get(Number(req.params.id));if(!resource||!resource.file_key)return res.status(404).json({error:'Resource file not found.'});if(req.session.user.role!=='admin'&&(resource.visibility!=='published'||resource.publication_status!=='published'))return res.status(404).json({error:'Resource file not found.'});try{const content=await getBuffer(resource.file_key);res.setHeader('Content-Type',resource.mime_type||'application/octet-stream');res.setHeader('Content-Disposition',`inline; filename="${String(resource.original_filename||'resource').replace(/["\\\r\n]/g,'_')}"`);res.setHeader('X-Content-Type-Options','nosniff');res.send(content);}catch{res.status(404).json({error:'Resource file not found.'});}});
function multipartUpload(req,res,next){const type=req.headers['content-type']||'';const match=type.match(/^multipart\/form-data;\s*boundary=(?:"([^"]+)"|([^;]+))/i);if(!match)return res.status(400).json({error:'Expected a multipart file upload.'});const declared=Number(req.headers['content-length']||0);if(declared>getMaxBytes()+256*1024)return res.status(413).json({error:`Upload exceeds the ${Math.floor(getMaxBytes()/1024/1024)} MB limit.`});const boundary=Buffer.from(`--${match[1]||match[2]}`);const chunks=[];let length=0,tooLarge=false;req.on('data',chunk=>{length+=chunk.length;if(length>getMaxBytes()+256*1024){tooLarge=true;chunks.length=0;return;}if(!tooLarge)chunks.push(chunk);});req.on('end',()=>{if(tooLarge)return res.status(413).json({error:`Upload exceeds the ${Math.floor(getMaxBytes()/1024/1024)} MB limit.`});const buffer=Buffer.concat(chunks);const fields={};let file=null;let cursor=0;while(true){const start=buffer.indexOf(boundary,cursor);if(start<0)break;let headerStart=start+boundary.length;if(buffer.subarray(headerStart,headerStart+2).toString()==='--')break;if(buffer.subarray(headerStart,headerStart+2).toString()==='\r\n')headerStart+=2;const headerEnd=buffer.indexOf(Buffer.from('\r\n\r\n'),headerStart);if(headerEnd<0)break;const headers=buffer.subarray(headerStart,headerEnd).toString('utf8');const next=buffer.indexOf(boundary,headerEnd+4);if(next<0)break;let end=next;if(buffer.subarray(end-2,end).toString()==='\r\n')end-=2;const content=buffer.subarray(headerEnd+4,end);const disposition=headers.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1]||'';const name=disposition.match(/name="([^"]+)"/)?.[1];const filename=disposition.match(/filename="([^"]*)"/)?.[1];const mime=headers.match(/content-type:\s*([^\r\n]+)/i)?.[1]?.trim().toLowerCase()||'application/octet-stream';if(filename!==undefined){if(filename){if(file)return res.status(400).json({error:'Upload one file at a time.'});file={originalname:path.basename(filename.replace(/\\/g,'/')),mimetype:mime,size:content.length,buffer:content};}}else if(name)fields[name]=content.toString('utf8');cursor=next;}req.body=fields;req.file=file;next();});req.on('error',()=>{if(!res.headersSent)res.status(400).json({error:'Upload could not be read.'});});}
const resourceUrl=z.string().trim().max(2000).refine(value=>{if(/^\/api\/resources\/\d+\/file$/.test(value))return true;try{const parsed=new URL(value);return ['https:','http:'].includes(parsed.protocol);}catch{return false;}},{message:'Enter a valid HTTP(S) URL or resource file path.'});
const resourceSchema=z.object({topic_id:z.number().int(),title:z.string().trim().min(2).max(150),kind:z.enum(['video','documentation','website','notes','practice','book','pdf','image','video_file','youtube','external_link','notes_file','reference','practice_file']),resource_type:z.enum(['link','pdf','image','video','youtube','external_link','notes','reference','practice','pyq']).default('link'),url:resourceUrl.optional().or(z.literal('')),description:z.string().max(1000).default(''),verified:z.boolean().default(false),visibility:z.enum(['published','private']).default('published'),publication_status:z.enum(['draft','published','archived']).default('published'),tags:z.array(z.string().trim().min(1).max(30)).max(20).default([])});
async function logAdmin(userId,action,type,id,details={}){await db.prepare('INSERT INTO admin_activity(admin_user_id,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)').run(userId,action,type,id,JSON.stringify(details));}
function legacyResourceKind(resourceType,requestedKind){if(['video','youtube'].includes(resourceType))return 'video';if(['external_link'].includes(resourceType))return 'website';if(['practice'].includes(resourceType))return 'practice';if(['book'].includes(requestedKind))return 'book';if(['documentation'].includes(requestedKind))return 'documentation';if(['website','video','practice','notes'].includes(requestedKind))return requestedKind;return 'notes';}
app.post('/api/admin/resources',requireAuth,requireAdmin,async (req,res)=>{const p=resourceSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});if(!await db.prepare('SELECT 1 FROM topics WHERE id=?').get(p.data.topic_id))return res.status(400).json({error:'Choose an existing topic.'});const d=p.data;if(!d.url)return res.status(400).json({error:'Enter a valid external URL or upload a file.'});const info=await db.prepare(`INSERT INTO resources(topic_id,title,kind,url,description,verified,resource_type,visibility,publication_status,tags) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(d.topic_id,d.title,legacyResourceKind(d.resource_type,d.kind),d.url,d.description,+d.verified,d.resource_type,d.visibility,d.publication_status,JSON.stringify(d.tags));await logAdmin(req.session.user.id,'create','resource',info.lastInsertRowid,{title:d.title});res.status(201).json({id:info.lastInsertRowid});});
app.put('/api/admin/resources/:id',requireAuth,requireAdmin,async (req,res)=>{const p=resourceSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});if(!await db.prepare('SELECT 1 FROM topics WHERE id=?').get(p.data.topic_id))return res.status(400).json({error:'Choose an existing topic.'});const d=p.data;const info=await db.prepare(`UPDATE resources SET topic_id=?,title=?,kind=?,url=?,description=?,verified=?,resource_type=?,visibility=?,publication_status=?,tags=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(d.topic_id,d.title,legacyResourceKind(d.resource_type,d.kind),d.url,d.description,+d.verified,d.resource_type,d.visibility,d.publication_status,JSON.stringify(d.tags),Number(req.params.id));if(!info.changes)return res.status(404).json({error:'Resource not found.'});await logAdmin(req.session.user.id,'update','resource',Number(req.params.id),{title:d.title});res.json({ok:true});});
app.delete('/api/admin/resources/:id',requireAuth,requireAdmin,async (req,res)=>{const resource=await db.prepare('SELECT * FROM resources WHERE id=?').get(Number(req.params.id));if(!resource)return res.status(404).json({error:'Resource not found.'});await db.prepare('DELETE FROM resources WHERE id=?').run(resource.id);if(resource.file_key)await deleteKey(resource.file_key);if(resource.thumbnail_key)await deleteKey(resource.thumbnail_key);await logAdmin(req.session.user.id,'delete','resource',resource.id,{title:resource.title});res.json({ok:true});});
app.post('/api/admin/resources/upload',requireAuth,requireAdmin,multipartUpload,async (req,res)=>{
 const p=z.object({id:z.coerce.number().int().positive().optional(),topic_id:z.coerce.number().int().positive(),title:z.string().trim().min(2).max(150),description:z.string().max(1000).default(''),resource_type:z.enum(['pdf','pyq','image','video','notes','reference','practice']).default('pdf'),visibility:z.enum(['published','private']).default('published'),publication_status:z.enum(['draft','published','archived']).default('draft'),tags:z.string().max(500).default(''),verified:z.string().optional()}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:validationError(p.error)});
 if(!await db.prepare('SELECT 1 FROM topics WHERE id=?').get(p.data.topic_id))return res.status(400).json({error:'Choose an existing topic.'});
 const old=p.data.id?await db.prepare('SELECT * FROM resources WHERE id=?').get(p.data.id):null;
 if(p.data.id&&!old)return res.status(404).json({error:'Resource not found.'});
 const file=req.file;if(!file&&!old)return res.status(400).json({error:'Choose a file to upload.'});
 let descriptor=null,stored=false;
 if(file){try{descriptor=safeKey(file.originalname,file.mimetype,file.size);validateSignature(descriptor.type,file.buffer);}catch(e){return res.status(400).json({error:e.message});}
 if((['pdf','pyq'].includes(p.data.resource_type)&&descriptor.type!=='pdf')||(p.data.resource_type==='image'&&descriptor.type!=='image')||(p.data.resource_type==='video'&&descriptor.type!=='video_file')||(['notes','reference','practice'].includes(p.data.resource_type)&&!['pdf','image','video_file','notes_file'].includes(descriptor.type)))return res.status(400).json({error:'The uploaded file type does not match the selected resource type.'});
 }
 try{
  if(file){await saveBuffer(descriptor.key,file.buffer,file.mimetype);stored=true;}
  const kinds={pdf:'notes',image:'notes',video_file:'video',notes_file:'notes'};
  const tags=JSON.stringify(p.data.tags.split(',').map(x=>x.trim()).filter(Boolean));let id=p.data.id;
  if(old){const key=descriptor?.key||old.file_key;const original=descriptor?path.basename(file.originalname):old.original_filename;const mime=descriptor?file.mimetype:old.mime_type;const size=descriptor?file.size:old.file_size;
   await db.prepare(`UPDATE resources SET topic_id=?,title=?,kind=?,url=?,description=?,verified=?,resource_type=?,visibility=?,publication_status=?,tags=?,file_key=?,original_filename=?,mime_type=?,file_size=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(p.data.topic_id,p.data.title,kinds[descriptor?.type]||old.kind,`/api/resources/${old.id}/file`,p.data.description,p.data.verified==='on'?1:old.verified,p.data.resource_type,p.data.visibility,p.data.publication_status,tags,key,original,mime,size,old.id);id=old.id;
   if(descriptor&&old.file_key)await deleteKey(old.file_key);
  }else{
   const info=await db.prepare(`INSERT INTO resources(topic_id,title,kind,url,description,verified,resource_type,visibility,publication_status,file_key,original_filename,mime_type,file_size,tags) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(p.data.topic_id,p.data.title,kinds[descriptor.type],'/api/resources/pending',p.data.description,p.data.verified==='on'?1:0,p.data.resource_type,p.data.visibility,p.data.publication_status,descriptor.key,path.basename(file.originalname),file.mimetype,file.size,tags);id=info.lastInsertRowid;
   await db.prepare('UPDATE resources SET url=? WHERE id=?').run(`/api/resources/${id}/file`,id);
  }
  await logAdmin(req.session.user.id,old?'replace':'upload','resource',id,{title:p.data.title,fileType:descriptor?.type});res.status(old?200:201).json({id,url:`/api/resources/${id}/file`});
 }catch(e){if(stored&&descriptor)await deleteKey(descriptor.key).catch(()=>{});console.error(e);res.status(500).json({error:'File upload could not be saved.'});}
});
app.get('/api/admin/activity',requireAuth,requireAdmin,async (_req,res)=>res.json(await db.prepare(`SELECT a.*,u.name AS admin_name FROM admin_activity a LEFT JOIN users u ON u.id=a.admin_user_id ORDER BY a.created_at DESC LIMIT 25`).all()));

// Administrator management endpoints. All mutations are role-gated and validated.
app.get('/api/admin/stats',requireAuth,requireAdmin,async (_req,res)=>{const [students,assessments,questions,resources,subjects,units,topics,uploads]=await Promise.all([db.prepare("SELECT COUNT(*) n FROM users WHERE role='student'").get(),db.prepare('SELECT COUNT(*) n FROM assessments WHERE completed_at IS NOT NULL').get(),db.prepare('SELECT COUNT(*) n FROM questions').get(),db.prepare('SELECT COUNT(*) n FROM resources').get(),db.prepare('SELECT COUNT(*) n FROM subjects').get(),db.prepare('SELECT COUNT(*) n FROM units').get(),db.prepare('SELECT COUNT(*) n FROM topics').get(),db.prepare('SELECT COUNT(*) n FROM resources WHERE file_key IS NOT NULL').get()]);res.json({students:students.n,assessments:assessments.n,questions:questions.n,resources:resources.n,subjects:subjects.n,units:units.n,topics:topics.n,uploads:uploads.n});});
app.get('/api/admin/questions',requireAuth,requireAdmin,async (_req,res)=>res.json((await db.prepare(`SELECT q.*,s.code,s.name AS subject_name,u.number AS unit_number,t.title AS topic_title FROM questions q JOIN subjects s ON s.id=q.subject_id JOIN units u ON u.id=q.unit_id JOIN topics t ON t.id=q.topic_id ORDER BY q.created_at DESC`).all()).map(q=>({...q,options:JSON.parse(q.options)}))));
const questionSchema=z.object({subject_id:z.number().int(),unit_id:z.number().int(),topic_id:z.number().int(),text:z.string().trim().min(10).max(2000),type:z.enum(['mcq','multiple_select','true_false','short_answer']),options:z.array(z.string().trim().min(1).max(200)).max(8).default([]),correct_answer:z.union([z.string().min(1).max(500),z.array(z.string().min(1).max(200))]),explanation:z.string().max(2000).default(''),difficulty:z.enum(['easy','medium','hard']).default('medium'),marks:z.number().positive().max(100).default(1),is_demo:z.boolean().default(false)}).superRefine((q,ctx)=>{
 if(['mcq','multiple_select'].includes(q.type)&&q.options.length<2)ctx.addIssue({code:'custom',message:'Choice questions need at least two options.'});
 if(q.type==='mcq'&&(typeof q.correct_answer!=='string'||!q.options.includes(q.correct_answer)))ctx.addIssue({code:'custom',message:'Correct answer must match one option.'});
 if(q.type==='multiple_select'&&(!Array.isArray(q.correct_answer)||!q.correct_answer.length||q.correct_answer.some(a=>!q.options.includes(a))))ctx.addIssue({code:'custom',message:'Select one or more correct options from the options list.'});
 if(q.type==='true_false'&&!['true','false'].includes(String(q.correct_answer)))ctx.addIssue({code:'custom',message:'True/false answer must be true or false.'});
});
async function validateQuestionLinks(q){return db.prepare('SELECT 1 FROM units u JOIN topics t ON t.unit_id=u.id WHERE u.id=? AND u.subject_id=? AND t.id=?').get(q.unit_id,q.subject_id,q.topic_id);}
app.post('/api/admin/questions',requireAuth,requireAdmin,async (req,res)=>{const p=questionSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});const q=p.data;if(!await validateQuestionLinks(q))return res.status(400).json({error:'Subject, unit and topic must match.'});const correct=Array.isArray(q.correct_answer)?JSON.stringify(q.correct_answer):String(q.correct_answer);const info=await db.prepare('INSERT INTO questions(subject_id,unit_id,topic_id,text,type,options,correct_answer,explanation,difficulty,marks,is_demo) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(q.subject_id,q.unit_id,q.topic_id,q.text,q.type,JSON.stringify(q.options),correct,q.explanation,q.difficulty,q.marks,+q.is_demo);res.status(201).json({id:info.lastInsertRowid});});
app.put('/api/admin/questions/:id',requireAuth,requireAdmin,async (req,res)=>{const p=questionSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});const q=p.data;if(!await validateQuestionLinks(q))return res.status(400).json({error:'Subject, unit and topic must match.'});const correct=Array.isArray(q.correct_answer)?JSON.stringify(q.correct_answer):String(q.correct_answer);const info=await db.prepare('UPDATE questions SET subject_id=?,unit_id=?,topic_id=?,text=?,type=?,options=?,correct_answer=?,explanation=?,difficulty=?,marks=?,is_demo=? WHERE id=?').run(q.subject_id,q.unit_id,q.topic_id,q.text,q.type,JSON.stringify(q.options),correct,q.explanation,q.difficulty,q.marks,+q.is_demo,Number(req.params.id));if(!info.changes)return res.status(404).json({error:'Question not found.'});res.json({ok:true});});
app.delete('/api/admin/questions/:id',requireAuth,requireAdmin,async (req,res)=>{const info=await db.prepare('DELETE FROM questions WHERE id=?').run(Number(req.params.id));if(!info.changes)return res.status(404).json({error:'Question not found.'});res.json({ok:true});});
app.get('/api/admin/users',requireAuth,requireAdmin,async (_req,res)=>res.json(await db.prepare(`SELECT u.id,u.name,u.email,u.created_at,(SELECT COUNT(*) FROM assessments a WHERE a.user_id=u.id AND a.completed_at IS NOT NULL) AS assessments FROM users u WHERE u.role='student' ORDER BY u.created_at DESC`).all()));
app.get('/api/admin/syllabus',requireAuth,requireAdmin,async (_req,res)=>res.json(await db.prepare(`SELECT s.id AS subject_id,s.code,s.name,s.semester,u.id AS unit_id,u.number,u.title AS unit_title,t.id AS topic_id,t.title AS topic_title,t.position FROM subjects s JOIN units u ON u.subject_id=s.id JOIN topics t ON t.unit_id=u.id ORDER BY s.semester,s.code,u.number,t.position`).all()));
app.put('/api/admin/subjects/:id',requireAuth,requireAdmin,async (req,res)=>{const p=z.object({name:z.string().trim().min(2).max(120),semester:z.number().int().min(1).max(12)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});const x=await db.prepare('UPDATE subjects SET name=?,semester=? WHERE id=?').run(p.data.name,p.data.semester,Number(req.params.id));if(!x.changes)return res.status(404).json({error:'Subject not found.'});res.json({ok:true});});
app.put('/api/admin/units/:id',requireAuth,requireAdmin,async (req,res)=>{const p=z.object({number:z.number().int().min(1).max(99),title:z.string().trim().min(2).max(180)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});try{const x=await db.prepare('UPDATE units SET number=?,title=? WHERE id=?').run(p.data.number,p.data.title,Number(req.params.id));if(!x.changes)return res.status(404).json({error:'Unit not found.'});res.json({ok:true});}catch{res.status(409).json({error:'That unit number is already used in this subject.'});}});
app.put('/api/admin/topics/:id',requireAuth,requireAdmin,async (req,res)=>{const p=z.object({title:z.string().trim().min(3).max(250),position:z.number().int().min(0).max(999)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});try{const x=await db.prepare('UPDATE topics SET title=?,position=? WHERE id=?').run(p.data.title,p.data.position,Number(req.params.id));if(!x.changes)return res.status(404).json({error:'Topic not found.'});res.json({ok:true});}catch{res.status(409).json({error:'This topic already exists in that unit.'});}});
app.post('/api/admin/topics',requireAuth,requireAdmin,async (req,res)=>{const p=z.object({unit_id:z.number().int(),title:z.string().trim().min(3).max(250),position:z.number().int().min(0).max(999)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:validationError(p.error)});if(!await db.prepare('SELECT 1 FROM units WHERE id=?').get(p.data.unit_id))return res.status(400).json({error:'Choose an existing unit.'});try{const x=await db.prepare('INSERT INTO topics(unit_id,title,position) VALUES(?,?,?)').run(p.data.unit_id,p.data.title,p.data.position);res.status(201).json({id:x.lastInsertRowid});}catch{res.status(409).json({error:'This topic already exists in that unit.'});}});
app.delete('/api/admin/topics/:id',requireAuth,requireAdmin,async (req,res)=>{const info=await db.prepare('DELETE FROM topics WHERE id=?').run(Number(req.params.id));if(!info.changes)return res.status(404).json({error:'Topic not found.'});res.json({ok:true});});

app.get('/api/admin/export',requireAuth,requireAdmin,async (_req,res)=>{
 const syllabus={source:JSON.parse(require('node:fs').readFileSync(path.join(__dirname,'..','data','syllabus.json'),'utf8')).source,subjects:await db.prepare(`SELECT s.code,s.name,s.semester,u.number AS unit_number,u.title AS unit,t.id AS topic_id,t.title AS topic,t.position FROM subjects s JOIN units u ON u.subject_id=s.id JOIN topics t ON t.unit_id=u.id ORDER BY s.code,u.number,t.position`).all()};
 const question=(await db.prepare(`SELECT s.code AS subject,u.number AS unit_number,t.title AS topic,q.text,q.type,q.options,q.correct_answer,q.explanation,q.difficulty,q.marks,q.is_demo FROM questions q JOIN subjects s ON s.id=q.subject_id JOIN units u ON u.id=q.unit_id JOIN topics t ON t.id=q.topic_id ORDER BY q.id`).all()).map(q=>({...q,options:JSON.parse(q.options)}));
 const resource=await db.prepare(`SELECT s.code AS subject,t.title AS topic,r.title,r.kind,r.url,r.description,r.verified FROM resources r JOIN topics t ON t.id=r.topic_id JOIN units u ON u.id=t.unit_id JOIN subjects s ON s.id=u.subject_id`).all();
 const stats=await db.prepare(`SELECT u.id,u.name,u.email,u.role,u.created_at,COUNT(DISTINCT a.id) AS assessments FROM users u LEFT JOIN assessments a ON a.user_id=u.id AND a.completed_at IS NOT NULL GROUP BY u.id`).all();
 res.setHeader('Content-Disposition','attachment; filename="mindmap-data-export.json"');res.json({exportedAt:new Date().toISOString(),syllabus,questions:question,resources,users:stats});
});
app.use('/api',(_req,res)=>res.status(404).json({error:'API route not found.'}));
app.get(['/admin','/admin/*path'],(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.get('*path',(_req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});

async function bootstrapAdmin(){
 const email=process.env.ADMIN_EMAIL;const password=process.env.ADMIN_PASSWORD;
 if(!email){console.log('Admin bootstrap skipped. Set ADMIN_EMAIL to configure the administrator account.');return;}
 const existing=await db.prepare('SELECT id,role FROM users WHERE email=?').get(email.toLowerCase());
 if(existing){if(existing.role!=='admin'){await db.prepare("UPDATE users SET role='admin' WHERE id=?").run(existing.id);console.log(`Configured administrator account was promoted: ${email}`);}else console.log(`Administrator account is ready: ${email}`);return;}
 if(!password){console.warn('Admin bootstrap skipped: configured email has no account yet; set ADMIN_PASSWORD to create it.');return;}
 if(password.length<12){console.warn('Admin bootstrap skipped: ADMIN_PASSWORD must contain at least 12 characters.');return;}
 const hash=await bcrypt.hash(password,12);await db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')").run('MindMap Administrator',email.toLowerCase(),hash);console.log(`Initial administrator created: ${email}`);
}

initDb().then(seedSyllabus).then(bootstrapAdmin).then(()=>app.listen(port,'0.0.0.0',()=>console.log(`MindMap running on port ${port}`))).catch(async e=>{console.error('Startup failed:',e);await db.close();process.exitCode=1;});
