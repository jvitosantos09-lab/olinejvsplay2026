// JVS PLAY — Netlify Function / JSONBin bridge
// Environment variables required in Netlify:
// JSONBIN_MASTER_KEY = your JSONBin Master Key
// JSONBIN_BIN_ID    = the ID of the private JSONBin containing the JVS data
// JVS_ACCESS_PASSWORD = the shared password for authorized JVS users
//
// The JSONBin key never reaches the browser.

const JSONBIN_BASE = 'https://api.jsonbin.io/v3';

function json(body, status=200){
  return new Response(JSON.stringify(body), {
    status,
    headers:{
      'Content-Type':'application/json; charset=utf-8',
      'Cache-Control':'no-store',
      'Access-Control-Allow-Origin':'*',
      'Access-Control-Allow-Headers':'Content-Type, X-JVS-Session',
      'Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'
    }
  });
}

function env(name){
  return (process.env[name] || '').trim();
}

function makeToken(password){
  // The browser only needs an opaque short-lived-ish session token.
  // It is not the JSONBin key.
  const raw = `${password}|${env('JVS_ACCESS_PASSWORD')}`;
  let h=2166136261;
  for(let i=0;i<raw.length;i++){h^=raw.charCodeAt(i);h=Math.imul(h,16777619);}
  return (h>>>0).toString(16);
}

function authorized(req){
  const expected=env('JVS_ACCESS_PASSWORD');
  if(!expected)return false;
  const supplied=req.headers.get('X-JVS-Session') || '';
  return supplied === makeToken(expected);
}

async function jsonbinRequest(method, path, body){
  const key=env('JSONBIN_MASTER_KEY');
  const id=env('JSONBIN_BIN_ID');
  if(!key || !id) throw new Error('JSONBin não configurado na Netlify.');
  const headers={
    'X-Master-Key':key,
    'Content-Type':'application/json',
    'X-Bin-Versioning':'true'
  };
  const response=await fetch(`${JSONBIN_BASE}/b/${id}${path||''}`,{
    method,headers,
    ...(body===undefined?{}:{body:JSON.stringify(body)})
  });
  const text=await response.text();
  let data=null;
  try{data=JSON.parse(text);}catch(_){data={message:text};}
  if(!response.ok){
    const err=new Error(data?.message || `JSONBin HTTP ${response.status}`);
    err.status=response.status;
    throw err;
  }
  return data;
}

export default async (req) => {
  if(req.method==='OPTIONS') return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, X-JVS-Session','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'}});

  try{
    if(req.method==='POST'){
      const body=await req.json().catch(()=>({}));
      if(!body.password || body.password !== env('JVS_ACCESS_PASSWORD')){
        return json({message:'Código de acesso inválido.'},401);
      }
      return json({ok:true,token:makeToken(body.password)});
    }

    if(!authorized(req)) return json({message:'Sessão não autorizada.'},401);

    if(req.method==='GET'){
      const result=await jsonbinRequest('GET','?meta=false');
      // Supports both the new envelope and an older raw JVS database.
      const record=result?.record ?? result;
      if(record && record.data && record.updatedAt){
        return json({ok:true,payload:record.data,updatedAt:record.updatedAt});
      }
      return json({ok:true,payload:record,updatedAt:''});
    }

    if(req.method==='PUT'){
      const body=await req.json();
      if(!body || typeof body.payload!=='object'){
        return json({message:'Payload JVS inválido.'},400);
      }
      const envelope={
        version:1,
        updatedAt:new Date().toISOString(),
        data:body.payload
      };
      const result=await jsonbinRequest('PUT','',envelope);
      return json({ok:true,updatedAt:envelope.updatedAt,version:result?.metadata?.version||null});
    }

    return json({message:'Método não permitido.'},405);
  }catch(error){
    console.error('JVS JSONBin Function:',error);
    return json({message:error.message||'Erro interno da API.'},500);
  }
};

export const config = { path:'/api/jvs-cloud' };
