// Diagnostics accept known event codes only, never arbitrary Error/string data.
const CODES=new Set(['starting','running','retrying','relink_required','blocked','stopped','ready','shutdown','startup_failed','request_failed']);
export function safeLog(code,write=line=>process.stderr.write(line+'\n')){
 write(JSON.stringify({time:new Date().toISOString(),event:CODES.has(code)?code:'request_failed'}));
}
