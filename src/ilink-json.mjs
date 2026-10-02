// Node >=24 exposes the original JSON numeric token to the reviver.
// Never recover an ID with String(value) after floating-point rounding.
export function parseIlinkJson(raw) {
 return JSON.parse(raw,(key,value,context)=>{
  if(key!=='message_id'||typeof value!=='number')return value;
  if(typeof context?.source!=='string')throw Error('ilink_lossless_json_required');
  return context.source;
 });
}
const MAX_UINT64=18446744073709551615n;
export function normalizeMessageId(value) {
 if(typeof value==='number')return Number.isSafeInteger(value)&&value>=0?String(value):null;
 if(typeof value!=='string'||!/^[0-9]{1,20}$/.test(value))return null;
 const id=BigInt(value);
 return id<=MAX_UINT64?id.toString():null;
}
