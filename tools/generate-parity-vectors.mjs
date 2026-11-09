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
const add=(name,s)=>{s=clean(s);const r=detectAutomation(s,{fontStackCount:17});detect.push({name,input:s,result:{pass:r.pass,blockedBy:r.blockedBy,riskFlags:r.riskFlags}});};
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
 ['unreachable',{hp:null},{blockAutomatedBrowsers:true}],['legacy',{lw:1},{blockAutomatedInteractions:true}],['isolated',{is:1},{blockAutomatedBrowsers:true}],['legacy report',{lw:1},{}],['isolated report',{is:1},{}],['eval',{ce:2},{}],
 ['clicks',{ia:[3,0]},{detectAutomatedInteractions:true}],['keys block',{ia:[0,3]},{detectAutomatedInteractions:true,blockAutomatedInteractions:true}],['missing ia',{}, {detectAutomatedInteractions:true}],
 ['stale',{el:70000},{}],['future',{el:10000},{}],['unknown data',{unknown:1},{}],['bad version',{v:2},{}],['bad codes',{ag:['z','a']},{}],['many codes',{ag:Array.from({length:33},(_,i)=>'a'+String.fromCharCode(97+(i/26|0),97+i%26))},{}],['automation code',{ag:['automation']},{}],
 ['behavior missing',{}, {behavior:true}],['reduced behavior report',{lw:1},{behavior:true,behaviorEnforced:false}],['reduced behavior block',{lw:1},{behavior:true,behaviorEnforced:true}],['probe missing',{p:null},{blockAutomatedBrowsers:true}]
]){const m={...meta,...policy};check(name,m,payload(m,{...base,...over}));}
for(const [name,patch] of Object.entries({id:{i:'wrong'},extra:{evil:true},state:{state:{aaaa:1}},nonstr:{d:1},oversized:{d:' '.repeat(65537)},tampered:{d:payload(meta,{...base,ce:1}).d}}))check(name,meta,{...payload(meta,base),...patch});
const encoding=['plain','é中😀','\u2028\u2029',JSON.stringify({n:1e-7,b:1e21})].map(value=>({value,seed:12345678,hash:boundValues({...meta.binding,pv:[0,0,0,0],sl:[0,0,0,0]},value)}));
console.log(JSON.stringify({detect,verify,encoding},null,2));
