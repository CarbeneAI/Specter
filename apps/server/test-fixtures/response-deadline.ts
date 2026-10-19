import assert from 'node:assert/strict';
import { join } from 'node:path';
import { getScoringBackend, registerScoringBackend } from '../src/scorer';
const [scenario, directory, compositionMode] = process.argv.slice(2);
const models = scenario.startsWith('models-'), poll = scenario.startsWith('poll-');
const nativeThirty = scenario === 'models-native-30s';
const timeoutCase = scenario.includes('timeout') || nativeThirty;
const errorCase = scenario.includes('error');
const nativeTimeout = AbortSignal.timeout.bind(AbortSignal);
const requestedDeadlines: number[] = [];
const nativeSignals: AbortSignal[] = [];
// Most cases accelerate only the native signal. One retains the actual 30s.
AbortSignal.timeout = (ms: number) => {
 requestedDeadlines.push(ms);
 const signal = nativeTimeout(nativeThirty ? ms : Math.min(ms, 350));
 nativeSignals.push(signal);
 return signal;
};
process.env.WAZUH_DASHBOARD_USER = 'synthetic-reader';
process.env.WAZUH_DASHBOARD_PASSWORD = 'synthetic-placeholder';
process.env.WAZUH_CA_FILE = join(directory, 'ca.pem');
process.env.WAZUH_ALERTS_PATH = join(directory, 'missing.jsonl');
process.env.LEDGER_DB_PATH = join(directory, `${scenario}.sqlite`);
process.env.SPECTER_ENV_FILE = join(directory, 'missing.env');
process.env.WAZUH_POLL_INTERVAL = '60000';
const intervals: (() => Promise<void>)[] = [];
const originalInterval = globalThis.setInterval;
globalThis.setInterval = ((cb: () => Promise<void>) => { intervals.push(cb); return intervals.length as unknown as ReturnType<typeof setInterval>; }) as typeof setInterval;
let stream: ReadableStreamDefaultController<Uint8Array> | undefined;
let headerRelease: (() => void) | undefined;
let cancelled = false, requests = 0, notifications = 0, scoreCalls = 0;
const scoringBackend = getScoringBackend();
registerScoringBackend({
  name: 'deadline-fixture-counter',
  async score(alert, context) { scoreCalls++; return scoringBackend.score(alert, context); },
});
let phase: 'seed' | 'held' | 'recovery' = poll ? 'seed' : 'held';
const queries: any[] = [], handlerErrors: unknown[] = [], pending: Promise<unknown>[] = [];
function sample(second: number) {
 return { timestamp: `2026-10-19T12:00:${String(second).padStart(2,'0')}.000Z`, rule: { id:'100', level:5, description:'Synthetic deadline record' }, agent:{id:'001',name:'fixture'} };
}
function payload() {
 if(models) return {models:scenario==='models-empty'?[]:[{name:'synthetic-model'}]};
 return {timed_out:false,_shards:{total:1,successful:1,failed:0},hits:{total:{value:1,relation:'eq'},hits:[{_source:sample(phase==='seed'?10:phase==='recovery'?30:20)}]}};
}
const server = Bun.serve({hostname:'127.0.0.1',port:0,idleTimeout:60,
 ...(models?{}:{tls:{key:Bun.file(join(directory,'server.key')),cert:Bun.file(join(directory,'server.pem'))}}),
 async fetch(req) {
  requests++;if(!models) queries.push(await req.json());
  if(phase!=='held'||scenario==='models-empty')return Response.json(payload());
  if(scenario==='models-header-timeout'){await new Promise<void>(resolve=>{headerRelease=resolve;});return Response.json(payload());}
  return new Response(new ReadableStream<Uint8Array>({start(c){stream=c;c.enqueue(new TextEncoder().encode(' '));},cancel(){cancelled=true;}}),{status:errorCase?503:200,headers:{'content-type':'application/json'}});
 },error(error){handlerErrors.push(error);return new Response('Fixture handler failed',{status:500});}
});
process.env.WAZUH_DASHBOARD_URL=`https://127.0.0.1:${server.port}`;
const originalFetch=globalThis.fetch;
globalThis.fetch=(async(input:string|URL|Request,init?:RequestInit)=>{
 const url=new URL(input instanceof Request?input.url:String(input));assert.equal(url.hostname,'127.0.0.1','no external fixture requests');assert.equal(url.port,String(server.port));return originalFetch(input,init);
}) as typeof fetch;
async function waitFor(predicate:()=>boolean,ms=2000){const until=Date.now()+ms;while(!predicate()){assert.ok(Date.now()<until,'expected operation did not settle or reach its native server state');await Bun.sleep(5);}}
function releaseBody(){if(stream&&!cancelled){try{stream.enqueue(new TextEncoder().encode(errorCase?'synthetic upstream error':JSON.stringify(payload())));stream.close();}catch{/* Native abort may already close it. */}}}
const originalLog=console.log;
try{
 const client=await import('../src/pai-client');
 let ingestion:typeof import('../src/alert-ingest')|undefined;
 if(poll){
  ingestion=await import('../src/alert-ingest');let initialDone=false;
  console.log=(...args)=>{if(String(args[0]).startsWith('Initial poll complete'))initialDone=true;};
  ingestion.startAlertIngestion(()=>{notifications++;});await waitFor(()=>initialDone);assert.equal(ingestion.getRecentAlerts().length,1);phase='held';
 }
 const started=Date.now();let settled=false;let result:any;
 const operation=poll?intervals[0]!():models?client.getOllamaModels(`http://127.0.0.1:${server.port}`):client.searchWazuhAlerts({});
 pending.push(operation);operation.then(value=>{result=value;settled=true;});
 await waitFor(()=>!!stream||!!headerRelease||scenario==='models-empty');
 if(poll && compositionMode==='composed-guard' && !errorCase){
  assert.equal(settled,false,'guard probe must overlap an active consumed body');
  await intervals[0]!();
  assert.equal(requests,2,'held body must retain the composed single-flight guard');
 }
 if(timeoutCase){
  await waitFor(()=>settled,nativeThirty?38000:2200);
  if(nativeThirty)assert.ok(Date.now()-started>=29000,'unaccelerated case must actually wait for the declared deadline');
  if(models)assert.deepEqual(result,[]);else if(!poll){assert.ok(result.error);assert.equal(result.results.length,0);}
  if(stream){await waitFor(()=>cancelled);assert.throws(()=>stream!.enqueue(new TextEncoder().encode('late body')));}
 }else if(scenario.includes('error-cancel')){
  await waitFor(()=>settled&&cancelled);
  assert.ok(nativeSignals.every(signal=>!signal.aborted),'non-OK cancellation must happen before the deadline');
  if(models)assert.deepEqual(result,[]);assert.throws(()=>stream!.enqueue(new TextEncoder().encode('late body')));
 }else{
  if(scenario!=='models-empty'){await Bun.sleep(60);assert.equal(settled,false,'body must be consumed before result');releaseBody();}
  await waitFor(()=>settled);
  assert.ok(nativeSignals.every(signal=>!signal.aborted),'valid/error body completion must precede deadline');
  assert.equal(cancelled,false);
  if(models)assert.deepEqual(result,scenario==='models-empty'?[]:['synthetic-model']);
  else if(!poll){if(scenario==='search-http-error')assert.equal(result.error,'Indexer query failed: 503');else{assert.equal(result.error,undefined);assert.equal(result.results.length,1);}}
 }
 assert.ok(requestedDeadlines.length>0,'production path must request its native deadline');
 assert.ok(requestedDeadlines.every(ms=>ms===30000),'production deadline stays fixed 30s even in accelerated fixtures');
 if(poll){
  const failed=scenario==='poll-body-timeout'||scenario==='poll-error-cancel';
  assert.equal(ingestion!.getRecentAlerts().length,failed?1:2,'earlier memory must survive request failure');assert.equal(notifications,failed?1:2);assert.equal(scoreCalls,failed?1:2,'failed body must not reserve a scoring batch');
  phase='recovery';await intervals[0]!();assert.equal(ingestion!.getRecentAlerts().length,failed?2:3);assert.equal(scoreCalls,failed?2:3);assert.equal(notifications,failed?2:3);
  const gt=(query:any)=>query.query.bool.must.find((clause:any)=>clause.range)?.range.timestamp.gt;
  assert.equal(gt(queries[1]),sample(10).timestamp);assert.equal(gt(queries[2]),sample(failed?10:20).timestamp,'failed body must not advance cursor');
 }else if(timeoutCase||scenario.includes('error-cancel')){
  headerRelease?.();phase='recovery';
  if(models)assert.deepEqual(await client.getOllamaModels(`http://127.0.0.1:${server.port}`),['synthetic-model']);
  else assert.equal((await client.searchWazuhAlerts({})).error,undefined);
 }
 assert.deepEqual(handlerErrors,[]);console.log=originalLog;console.log(JSON.stringify({scenario,accelerated:!nativeThirty,requested_deadline_ms:30000,requests,stream_cancelled:cancelled,elapsed_ms:Date.now()-started}));
}finally{
 headerRelease?.();releaseBody();await Promise.allSettled(pending);console.log=originalLog;globalThis.setInterval=originalInterval;globalThis.fetch=originalFetch;AbortSignal.timeout=nativeTimeout;server.stop(true);
}
// Natural exit also verifies successful native timers do not pin the process.
