#!/usr/bin/env node
// Offline: node tools/generate-parity-vectors.mjs /path/to/cap > tests/fixtures/parity-vectors.json
// Source pinned in src/Instrumentation/UPSTREAM.md. Runs the real upstream functions.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=resolve(process.argv[2]);
const load=p=>import(pathToFileURL(resolve(root,p)).href);
const {detectAutomation}=await load('core/src/detect.js');
const {boundValues,serializeBound,verifyInstrumentationResult}=await load('core/src/instrumentation.js');
const test=readFileSync(resolve(root,'core/test/detect.test.js'),'utf8');
const defs=test.slice(test.indexOf('const frac'),test.indexOf('describe('));
const {chromeHuman,firefoxHuman,safariHuman}=await import('data:text/javascript;base64,'+Buffer.from(defs+'\nexport {chromeHuman,firefoxHuman,safariHuman};').toString('base64'));
const clean=x=>JSON.parse(JSON.stringify(x));
const detect=[];
const add=(name,s)=>{s=clean(s);const r=detectAutomation(s,{fontStackCount:17});detect.push({name,input:s,inputJson:JSON.stringify(s),result:{pass:r.pass,blockedBy:r.blockedBy,riskFlags:r.riskFlags}});};
for(const [name,make] of Object.entries({chrome:chromeHuman,firefox:firefoxHuman,safari:safariHuman})){
 add(name,make());
 for(const key of Object.keys(make())){
  const s=make();delete s[key];add(name+' missing '+key,s);
 }
}
const patches={
 webdriver:{webdriver:true}, stripped:{webdriver:undefined}, headless:{ua:'HeadlessChrome/151'}, quantized:{fontWidths:Array.from({length:17},(_,i)=>1200+i*3)}, blankWidths:{fontWidths:Array(17).fill(0)}, gecko:{oscpu:'Linux',deviceMemory:8},
 outer:{outerWH:[1000,1300]}, viewport:{innerWH:[1920,1080],outerWH:[1920,1200]}, blankBrands:{uaData:{brands:[],mobile:false}}, stealth:{stealth:{iframe:true,runtime:true}}, chromeMissing:{engine:{hasChrome:false}},
 worker:{workerNav:{platform:'Win32',hc:1}}, native:{tamper:{toDataURL:false},lies:['permissionsQuery']}, engine:{ua:'Mozilla/5.0 Safari/605.1',evalLen:33}, os:{ua:'Windows NT Chrome/151',activeText:['rgb(255, 0, 0)',false]},
 langs:{langs:[0,false]}, host:{host:{nav:{platform:'Win32',webdriver:true},doc:true,cdp:true,ha:['data-playwright']}}, cdp:{cdp:{trap:true,shadow:false}}, gpu:{gpu:{f:true,v:'NVIDIA'},mainNav:{gl:'Apple GPU'}},
 canvas:{cv:[0,100]}, arch:{hev:{ar:'arm'},na:255}, globals:{ig:['foo']}, devtools:{sd:['isTrusted','webdriver']}, order:{no:['webdriver']}, shader:{glsh:{r:'Apple GPU',t:'hlsl'}}, voices:{voices:[5,0]}, fonts:{fm:1200.88,fontWidths:Array(17).fill(1200.88)},
 linux:{ua:'Mozilla/5.0 Linux Chrome/151',screen:{dpr:1,width:1920,height:1080},fontWidths:Array.from({length:17},(_,i)=>1200+i*3)},
 mobile:{ua:'Mozilla/5.0 Android Chrome/151',uaData:{brands:['Chromium/151'],mobile:true},maxTouchPoints:5,mainNav:{platform:'Linux armv8l'},hev:{ar:'x86'},na:127}
};
for(const [name,p] of Object.entries(patches))add(name,{...chromeHuman(),...p});
for(const key of ['uaData','plugins','engine','screen','mainNav','tamper','outerWH','fontWidths','host','workerNav','hev','stealth','lies','ig','sd','no','cv','gpu','voices'])for(const value of [null,17,'bad',[],{}])add('malformed '+key+' '+JSON.stringify(value),{...chromeHuman(),[key]:value});
const now=1_000_000;
const meta={id:'0123456789abcdef0123456789abcdef',iat:now-1000,expires:now+60000,vars:['aaaa','bbbb','cccc','dddd'],binding:{pv:[-1234567,89012345,-123,777],sl:[123456,234567,345678,456789],hs:[89123456,987654321],j:[0,2]},blockAutomatedBrowsers:false,detectAutomatedInteractions:false,blockAutomatedInteractions:false,behavior:false,behaviorEnforced:false};
const base={v:1,el:100,p:chromeHuman(),vp:[945,868],hp:{nav:{brands:'Google Chrome/151'},cdp:false},ag:[],ce:0,ia:null,bh:null};
const payload=(m,d)=>{const serialized=serializeBound(clean(d));return {i:m.id,state:Object.fromEntries(m.vars.map((v,i)=>[v,boundValues(m.binding,serialized)[i]])),d:serialized};};
const verify=[];
const check=(name,m,p)=>{const r=verifyInstrumentationResult(m,p,now); const out={valid:r.valid};for(const k of ['reason','riskFlags','blockedBy','trace','agent'])if(r[k]!==undefined)out[k]=r[k];verify.push({name,meta:m,payload:p,now,result:out});};
check('valid',meta,payload(meta,base));
for(const [name,p] of Object.entries(patches)){
 const m={...meta,blockAutomatedBrowsers:true};const d={...base,p:{...chromeHuman(),...p}};check('gated '+name,m,payload(m,d));
}
for(const [name,over,policy] of [
 ['unreachable',{hp:null},{blockAutomatedBrowsers:true}],['legacy',{lw:1},{blockAutomatedInteractions:true}],['isolated',{is:1},{blockAutomatedBrowsers:true}],['legacy report',{lw:1},{}],['isolated report',{is:1},{}],['eval',{ce:2},{}],['null eval',{ce:null},{}],
 ['clicks',{ia:[3,0]},{detectAutomatedInteractions:true}],['keys block',{ia:[0,3]},{detectAutomatedInteractions:true,blockAutomatedInteractions:true}],['missing ia',{}, {detectAutomatedInteractions:true}],
 ['stale',{el:70000},{}],['future',{el:10000},{}],['unknown data',{unknown:1},{}],['bad version',{v:2},{}],['bad codes',{ag:['z','a']},{}],['many codes',{ag:Array.from({length:33},(_,i)=>'a'+String.fromCharCode(97+(i/26|0),97+i%26))},{}],['automation code',{ag:['automation']},{}],
 ['behavior missing',{}, {behavior:true}],['reduced behavior report',{lw:1},{behavior:true,behaviorEnforced:false}],['reduced behavior block',{lw:1},{behavior:true,behaviorEnforced:true}],['probe missing',{p:null},{blockAutomatedBrowsers:true}]
]){const m={...meta,...policy};check(name,m,payload(m,{...base,...over}));}
for(const [name,over] of Object.entries({badHost:{hp:{nav:{brands:{toString:1}}}},badMain:{p:{...chromeHuman(),mainNav:{brands:{toString:1}}}},badWebdriver:{p:{...chromeHuman(),webdriver:{toString:1}}},badUa:{p:{...chromeHuman(),ua:{toString:1}}},badBrands:{p:{...chromeHuman(),uaData:{brands:[{toString:1}]}}},badLangs:{p:{...chromeHuman(),langs:[{toString:1},true]}},badPrototype:{hp:{constructor:{evil:1}}},nullTamper:{p:{...chromeHuman(),tamper:null}}}))check(name,meta,payload(meta,{...base,...over}));
for(const count of [20000,33000])check('unicode boundary '+count,meta,payload(meta,{...base,hp:{tag:'😀'.repeat(count)}}));
for(const [name,patch] of Object.entries({id:{i:'wrong'},extra:{evil:true},state:{state:{aaaa:1}},nonstr:{d:1},oversized:{d:' '.repeat(65537)},tampered:{d:payload(meta,{...base,ce:1}).d}}))check(name,meta,{...payload(meta,base),...patch});
const encoding=['plain','é中😀','\u2028\u2029',JSON.stringify({n:1e-7,b:1e21})].map(value=>({value,seed:12345678,hash:boundValues({...meta.binding,pv:[0,0,0,0],sl:[0,0,0,0]},value)}));
const {analyzeBehavior,validateTrace}=await load('core/src/behavior.js');
const {AGENT_ARTIFACTS,agentFromCodes,agentFromTrace,agentFromHeaders,summarizeAgent}=await load('core/src/agents.js');
const bsrc=readFileSync(resolve(root,'core/test/behavior.test.js'),'utf8');
const bdefs=bsrc.slice(bsrc.indexOf('const ENV'),bsrc.indexOf('describe('));
const {base:traceBase,humanMoves,pointerAct}=await import('data:text/javascript;base64,'+Buffer.from(bdefs+'\nexport {base,humanMoves,pointerAct};').toString('base64'));
const behavior=[];
const badd=(name,t,ctx={})=>{t=clean(t);behavior.push({name,input:t,ctx,invalid:validateTrace(t),result:analyzeBehavior(t,ctx)});};
badd('missing',null);badd('empty',{});badd('no interaction',traceBase());
const human=traceBase({m:humanMoves(512.4,331.7,4000),a:pointerAct()});
badd('human',human);badd('replay',human,{replayed:true});
for(const [name,patch] of Object.entries({untrusted:{tr:0},hidden:{hid:1},center:{cx:0,cy:0},leak:{sox:0,soy:0},instant:{u:4001},unseen:{t:50,u:55},key:{k:1,u:4001},click:{k:2},touch:{pt:2,cw:1,ch:1,pr:0.5}}))badd(name,{...human,a:{...human.a,...patch}});
for(const [name,patch] of Object.entries({warp:{m:[]},idle:{m:[],last:1},scroll:{us:3990},neverVisible:{vis:-1},slowClock:{res:20},n:{n:[1,2,0,0,0,0,0,1,3,4,2]}}))badd(name,{...human,...patch});
for(const step of [10,50,100,137])for(const dwell of [0,25,50])badd('typing '+step+' '+dwell,traceBase({k:Array.from({length:12},(_,i)=>[i*step,dwell])}));
for(const d of [0,0.003]){
 const m=Array.from({length:20},(_,i)=>[3500+i*20,100+i*12+(d?d*i*i*i:0),200+i*5+(d?d*i*i*i:0),1,0]);
 badd('path '+d,traceBase({m,a:pointerAct({x:m.at(-1)[1],y:m.at(-1)[2]})}));
}
for(const key of Object.keys(traceBase())){const t=traceBase();delete t[key];badd('missing '+key,t);}
for(const [name,patch] of Object.entries({res:{res:-1},env:{env:[0]},counters:{n:[-1,0,0,0,0,0,0,0,0,0]},moves:{m:Array(321).fill([1,2,3,1,0])},move:{m:[[1,2,3,1]]},order:{m:[[2000,1,1,1,0],[0,1,1,1,0]]},keys:{k:Array(65).fill([1,1])},key:{k:[[1,70000]]},activation:{a:{k:3}}}))badd('malformed '+name,{...traceBase(),...patch});
badd('strict',traceBase({m:[],a:pointerAct({cx:0,cy:0,u:4001}),last:1}),{strict:true,threshold:0.4});
const agents=[];
for(const code of Object.keys(AGENT_ARTIFACTS).concat(['unknown','automation'])){
 const input=[code];const found=agentFromCodes(input);agents.push({name:'code '+code,kind:'codes',input,found,result:summarizeAgent(found)});
}
for(const v of behavior.filter(v=>v.input&&v.invalid===null)){
 const found=agentFromTrace(v.input);agents.push({name:'trace '+v.name,kind:'trace',input:v.input,found,result:summarizeAgent(found)});
}
for(const ua of ['Claude-Agent/1','Google-Agent','Manus-User/1','ChatGPT-User/1','GrokAgent','Agent-NovaAct/1','TwinAgent/1','CloudflareBrowserRenderingCrawler/1','Claude-User','claude-code/1','Perplexity-User/1','MistralAI-User/1','meta-externalfetcher/1','HarkBot/1','Mozilla/5.0 (Macintosh) Claude/1.2.3 Chrome/130','Mozilla/5.0 Windows NT Chrome/151']){
 const input={'User-Agent':ua,'Sec-CH-UA-Platform':'"Linux"'};const found=agentFromHeaders(input);agents.push({name:'header '+ua,kind:'headers',input,found,result:summarizeAgent(found)});
}
for(const host of ['chatgpt.com','agent.bot.goog','api.manus.im','cursorusercontent.com','www.kernel.sh','foo.example.com','abc.keydirectory.signer.xyz.on.aws']){
 const input={'Signature-Agent':'sig="https://'+host+'"'};const found=agentFromHeaders(input);agents.push({name:'signature '+host,kind:'headers',input,found,result:summarizeAgent(found)});
}
const all={detect,verify,encoding,behavior,agents};
console.log('{\n'+Object.entries(all).map(([k,v])=>JSON.stringify(k)+': [\n'+v.map(x=>JSON.stringify(x)).join(',\n')+'\n]').join(',\n')+'\n}');
