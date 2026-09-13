const {createHash,createPrivateKey,createPublicKey,sign,verify}=require("node:crypto");
const J=x=>x===null?"null":typeof x==="string"?JSON.stringify(x):typeof x==="boolean"?String(x):typeof x==="number"&&Number.isSafeInteger(x)&&x>=0&&!Object.is(x,-0)?String(x):Array.isArray(x)?"["+x.map(J).join(",")+"]":typeof x==="object"?"{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+J(x[k])).join(",")+"}":(()=>{throw Error("SCHEMA")})();
const H=x=>createHash("sha256").update(x).digest("hex");
const D=(k,x)=>H("LAGI-BOND/"+k+"/1\n"+J(x));
const Z="0".repeat(64), A="a".repeat(64), id=p=>p+"_"+"0".repeat(21);
const seed="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const key=createPrivateKey({key:Buffer.from("302e020100300506032b657004220420"+seed,"hex"),format:"der",type:"pkcs8"});
const pk=createPublicKey(key).export({format:"der",type:"spki"}).subarray(-32).toString("hex");
const S=(kind,body)=>{const key_id=id("bnk"),hash=D(kind,{body,key_id});return {body,key_id,hash,sig:sign(null,Buffer.from("LAGI-BOND/sign/"+kind+"/1\n"+hash),key).toString("base64url")}};
const blob=(x,media_type="application/json")=>{const b=Buffer.from(media_type==="application/json"?J(x):x);return {hash:H(b),bytes:b.length,media_type,data:b.toString("base64url")}};
const ref=b=>({hash:b.hash,bytes:b.bytes,media_type:b.media_type});
const ok=value=>({ok:true,value});
const fail=(code,head=null)=>({ok:false,code,retryable:false,head});
const known=value=>({status:"KNOWN",value});
const F={profile:"bond.sim-procurement-draft/1",t:"2026-09-12T12:00:00.000Z",a:id("bac"),r:id("brc"),q:id("bnq"),tenant:id("bnt"),scope:id("bns"),principal:id("bnp"),run:"run-1",host:"host-1"};
F.pin={charter_id:"bch_000000000000000000000",version:1,charter_hash:A,manifest_hash:A,engine:"bedrock.eval/1"};
F.action={schema:"bond.action/1",profile:F.profile,tenant_id:F.tenant,scope_id:F.scope,action_id:F.a,principal_id:F.principal,action_class:"procurement.draft.create/1",resource:"drafts/"+F.a,expected:"ABSENT",draft:{status:"DRAFT",supplier_alias:"supplier-1",catalog_item:"item-1",quantity:1,quoted_minor:"10000",asset:"SIMUSD"},terms:{asset:"SIMUSD",amount_minor:"1000",owner:"operator-1",beneficiary:"beneficiary-1",task_id:"task-1",reserve_until:"2026-09-12T12:05:00.000Z",long_stop:"2026-10-27T12:00:00.000Z",trigger:"OPERATOR_REJECTION_OF_CONFIRMED_DRAFT"},policy_pin:F.pin,adapter_build:A,created_at:F.t,execute_before:"2026-09-12T12:00:30.000Z"};
F.ah=D("action",F.action);F.dh=H(J(F.action.draft));
F.plan={schema:"bond.undo-plan/1",action_hash:F.ah,adapter_build:A,operation:"draft.delete_if_created_version",resource:F.action.resource,require_status:"DRAFT",require_no_export:true,version_source:"FORWARD_RESULT",value_hash:F.dh,remedy_minor:"1000",asset:"SIMUSD",expires_at:F.action.terms.long_stop};
F.doc=blob({simulation:true,policy:"SIM-PAPER-1",terms:"Draft-only simulated remedy; no real insurance or redeemable funds."});
F.paper=S("paper",{schema:"bond.paper/1",paper_id:id("bni"),tenant_id:F.tenant,holder:F.principal,insurer_label:"Simulation paper issuer",policy_reference:"SIM-PAPER-1",document:ref(F.doc),reviewed_by:F.principal,reviewed_at:F.t,effective_at:"2026-09-01T00:00:00.000Z",expires_at:"2026-11-01T00:00:00.000Z",action_class:"procurement.draft.create/1",asset:"SIMUSD",stated_per_action_limit:"1000",exclusions_document:ref(F.doc),mode:"PAPER_ONLY",insurer_confirmed:false,aggregate_availability:"NOT_VERIFIED",coverage_verdict:"NOT_DETERMINED"});
F.actionBlob=blob(F.action);F.planBlob=blob(F.plan);F.paperBlob=blob(F.paper);
F.binding={action:ref(F.actionBlob),plan:ref(F.planBlob),paper:ref(F.paperBlob),trellis_run:F.run,trellis_host:F.host,trellis_task_ref:F.a};
const evidence=facts=>{const source=blob(facts);return {assertion:S("assertion",{schema:"bond.assertion/1",action_hash:F.ah,observed_at:F.t,source_profile:"fixture/1",source:ref(source),facts}),source}};
const eb=e=>blob(e.assertion);
const hold=(state,revision,op)=>evidence({kind:"HOLD",hold_id:"hold-1",revision,action_hash:F.ah,terms:F.action.terms,state,exclusive:true,operation_key:F.a+":"+op,journal_head:{seq:revision,hash:A},settlement_basis:["RELEASED","PAID"].includes(state)?"REQUEST":null});
F.ep=evidence({kind:"POLICY",purpose:"FORWARD",pin:F.pin,input_hash:D("request",{action_hash:F.ah,purpose:"FORWARD"}),verdict:"ALLOW",reason:"ALLOW_SCOPE",evaluated_at:F.t});
F.epu=evidence({kind:"POLICY",purpose:"UNDO",pin:F.pin,input_hash:D("request",{action_hash:F.ah,purpose:"UNDO"}),verdict:"ALLOW",reason:"ALLOW_SCOPE",evaluated_at:F.t});
F.eh=hold("HELD",1,"reserve");F.ee=hold("ENCUMBERED",2,"encumber");F.er=hold("RELEASED",3,"release");F.ey=hold("PAID",3,"pay");
F.ef=evidence({kind:"EFFECT",purpose:"FORWARD",operation_key:F.a+":create",outcome:"APPLIED",resource:F.action.resource,version:"v1",value_hash:F.dh,reason:"CREATED"});
F.eu=evidence({kind:"EFFECT",purpose:"UNDO",operation_key:F.a+":undo",outcome:"APPLIED",resource:F.action.resource,version:"v1",value_hash:F.dh,reason:"DELETED"});
F.en=evidence({kind:"RUN",run_id:F.run,host_id:F.host,task_ref:F.a,state:"ACTIVE",checkpoint:{seq:1,hash:A},policy_hash:A,complete_prefix:true});
F.ek=evidence({kind:"KILL",run_id:F.run,host_id:F.host,task_ref:F.a,state:"CERTIFIED",stopped_head:{seq:9,hash:A},gate_closed:true,empty_observed:true,audit_gap:false,external_effects:"NOT_REVERSED",remote_replication:"NOT_ATTESTED"});
F.advisory=blob({schema:"bond.advisory/1",action_hash:F.ah,kind:"GROUND_ADVISORY",verdict:"NOT_REQUESTED"});
const all=[F.actionBlob,F.planBlob,F.paperBlob,F.doc,F.advisory];
for(const name of ["ep","epu","eh","ee","er","ey","ef","eu","en","ek"]){all.push(eb(F[name]),F[name].source)}
const unique=bs=>Array.from(new Map(bs.map(b=>[b.hash,b])).values()).sort((a,b)=>a.hash<b.hash?-1:1);
const base={receipt_id:F.r,action_id:F.a,revision:0,phase:"STAGED",effect:"NOT_DISPATCHED",undo:"PLANNED",funds:"NONE",kill:"ARMED",review:"NONE",stop_latched:false,quarantined:false,pending:["RESERVE"],head:{seq:0,hash:Z}};
const make=()=>({view:structuredClone(base),entries:[],receipts:[],evidence:[]});
const push=(s,kind,data,changes={})=>{
  const seq=s.entries.length+1;
  const entry=S("entry",{schema:"bond.entry/1",tenant_id:F.tenant,action_id:F.a,action_hash:F.ah,event_id:"bnj_"+String(seq).padStart(21,"0"),seq,previous_hash:s.view.head.hash,recorded_at:F.t,actor:F.principal,kind,data});
  s.view=Object.assign({},s.view,changes,{revision:seq,head:{seq,hash:entry.hash}});s.entries.push(entry);
  for(const k of ["evidence","policy","runtime","hold","artifact"]){if(data[k])s.evidence.push(data[k])}
  s.evidence=unique(s.evidence);
  const residual=s.view.effect==="UNKNOWN"||s.view.undo==="UNKNOWN"?"UNKNOWN":s.view.undo==="FAILED"?"NOT_REVERSED":s.view.effect==="APPLIED"&&s.view.undo!=="APPLIED"?"DRAFT_PRESENT":"NONE";
  const remedy=s.view.review!=="REJECT"?"NOT_TRIGGERED":s.view.funds==="PAID"?"PAID":"DUE";
  const complete=s.view.phase==="CLOSED"&&s.view.kill==="CERTIFIED"&&s.view.pending.length===0&&!s.view.quarantined&&remedy!=="DUE";
  const body={schema:"bond.receipt/1",receipt_id:F.r,tenant_id:F.tenant,action_id:F.a,action_hash:F.ah,revision:seq,previous_receipt_hash:s.receipts.length?s.receipts.at(-1).hash:null,head:s.view.head,binding:F.binding,view:structuredClone(s.view),evidence:structuredClone(s.evidence),issued_at:F.t,simulation:true,assembly:complete?"COMPLETE":"INCOMPLETE",insurance:"PAPER_ONLY",residual_effect:residual,remedy,truth:"ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF"};
  s.receipts.push(S("receipt",body));return s;
};
const stage=()=>push(make(),"ActionStaged",{binding:F.binding});
const ready=()=>push(stage(),"HoldObserved",{evidence:ref(eb(F.eh))},{phase:"READY",funds:"HELD",pending:[]});
const created=()=>{const s=ready();push(s,"CommitRequested",{operation_key:F.a+":encumber"},{phase:"COMMITTING",pending:["ENCUMBER"]});push(s,"HoldObserved",{evidence:ref(eb(F.ee))},{funds:"ENCUMBERED",pending:[]});push(s,"DispatchLatched",{policy:ref(eb(F.ep)),runtime:ref(eb(F.en)),hold:ref(eb(F.ee)),fence:1,operation_key:F.a+":create",timing:{boot_id:"boot-1",runtime_observed_ms:0,admitted_ms:0}},{phase:"EXECUTING",effect:"PENDING",pending:["CREATE"]});return push(s,"EffectObserved",{evidence:ref(eb(F.ef))},{phase:"AWAITING_REVIEW",effect:"APPLIED",pending:[]})};
const accepted=()=>{const s=created();push(s,"ReviewAccepted",{principal_id:F.principal},{phase:"CLOSING",review:"ACCEPT",undo:"NOT_NEEDED",pending:["RELEASE"]});F.acceptHash=s.entries.at(-1).hash;push(s,"FundsObserved",{evidence:ref(eb(F.er))},{funds:"RELEASED",pending:[]});return push(s,"ActionClosed",{disposition:"RELEASE"},{phase:"CLOSED"})};
const rejected=()=>{const s=created();push(s,"ReviewRejected",{principal_id:F.principal,reason:"OPERATOR_REJECTED",policy:ref(eb(F.epu))},{phase:"COMPENSATING",review:"REJECT",undo:"PENDING",pending:["UNDO"]});push(s,"UndoObserved",{evidence:ref(eb(F.eu))},{phase:"CLOSING",undo:"APPLIED",pending:["PAY"]});push(s,"FundsObserved",{evidence:ref(eb(F.ey))},{funds:"PAID",pending:[]});return push(s,"ActionClosed",{disposition:"PAY"},{phase:"CLOSED"})};
const canceled=()=>{const s=ready();push(s,"ActionAborted",{reason:"CANCELED"},{phase:"CLOSING",undo:"NOT_NEEDED",pending:["RELEASE"]});push(s,"FundsObserved",{evidence:ref(eb(F.er))},{funds:"RELEASED",pending:[]});return push(s,"ActionClosed",{disposition:"RELEASE"},{phase:"CLOSED"})};
const stopped=()=>{const s=ready();push(s,"StopRequested",{principal_id:F.principal,operation_key:F.a+":stop"},{phase:"CLOSING",undo:"NOT_NEEDED",stop_latched:true,kill:"REQUESTED",pending:["RELEASE","STOP"]});return push(s,"KillObserved",{evidence:ref(eb(F.ek))},{kill:"CERTIFIED",pending:["RELEASE"]})};
F.S0=stage();F.S1=ready();F.S2=created();F.S3=accepted();F.S4=rejected();F.SC=canceled();F.SS=stopped();
for(const n of ["0","1","2","3","4","C","S"]){F["V"+n]=structuredClone(F["S"+n].view)}
F.SA=accepted();push(F.SA,"EvidenceAttached",{artifact:ref(F.advisory),purpose:"GROUND_ADVISORY"});F.VA=F.SA.view;
F.P0={schema:"bond.package/1",receipts:F.S0.receipts,entries:F.S0.entries,blobs:unique([F.actionBlob,F.planBlob,F.paperBlob,F.doc])};
F.verify0={integrity:"VALID",completeness:"INCOMPLETE",currentness:"PINNED_PREFIX",simulation:true,insurance:"PAPER_ONLY",truth:"ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF",head:F.V0.head,errors:[]};
F.notice=S("notice",{schema:"bond.notice/1",receipt_id:F.r,revision:1,previous_hash:null,reason:"HOSTING_WITHDRAWN",recorded_at:F.t});
F.trust={schema:"bond.trust/1",keys:[{key_id:id("bnk"),public_key_hex:pk,roles:["assertion","entry","http","notice","paper","receipt"],assertion_kinds:["EFFECT","HOLD","KILL","NO_HOLD","POLICY","RUN"],source_profiles:["fixture/1"],tenant_id:F.tenant,not_before:"2026-09-01T00:00:00.000Z",not_after:"2026-11-01T00:00:00.000Z",compromised_at:null}],allowed_adapter_builds:[A],expected_heads:[{receipt_id:F.r,head:F.V0.head}]};
F.complete=accepted();push(F.complete,"StopRequested",{principal_id:F.principal,operation_key:F.a+":stop"},{kill:"REQUESTED",stop_latched:true,pending:["STOP"]});push(F.complete,"KillObserved",{evidence:ref(eb(F.ek))},{kill:"CERTIFIED",pending:[]});
const completeBlobs=[F.actionBlob,F.planBlob,F.paperBlob,F.doc];
for(const name of ["ep","eh","ee","er","ef","en","ek"]){completeBlobs.push(eb(F[name]),F[name].source)}
F.PC={schema:"bond.package/1",receipts:F.complete.receipts,entries:F.complete.entries,blobs:unique(completeBlobs)};
const unsignedAuth={tenant_id:F.tenant,principal_id:F.principal,key_id:id("bnk"),request_id:F.q,method:"POST",target:"/v1/certificates",body_hash:H(J({package:F.P0,expected_host_revision:0})),issued_at:F.t,expires_at:"2026-09-12T12:05:00.000Z"};
F.httpAuth=Object.assign({},unsignedAuth,{sig:sign(null,Buffer.from("LAGI-BOND/sign/request/1\n"+D("request",unsignedAuth)),key).toString("base64url")});
F.httpHeader=Buffer.from(J(F.httpAuth)).toString("base64url");
if(pk!=="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")throw Error("KEY_FIXTURE");
const signedObjects=[["paper",F.paper],["notice",F.notice]];
for(const s of [F.S0,F.S1,F.S2,F.S3,F.S4,F.SC,F.SS,F.SA,F.complete]){for(const e of s.entries)signedObjects.push(["entry",e]);for(const r of s.receipts)signedObjects.push(["receipt",r])}
for(const name of ["ep","epu","eh","ee","er","ey","ef","eu","en","ek"])signedObjects.push(["assertion",F[name].assertion]);
for(const [kind,obj] of signedObjects){if(obj.hash!==D(kind,{body:obj.body,key_id:obj.key_id})||!verify(null,Buffer.from("LAGI-BOND/sign/"+kind+"/1\n"+obj.hash),createPublicKey(key),Buffer.from(obj.sig,"base64url")))throw Error("SIGNATURE_FIXTURE")}
module.exports={F,J,H,D,S,blob,ref,ok,fail,known};
