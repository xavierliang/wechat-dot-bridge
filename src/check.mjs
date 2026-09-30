import {readdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
for(const file of await readdir(new URL('.',import.meta.url))){if(file.endsWith('.mjs')){const result=spawnSync(process.execPath,['--check',new URL(file,import.meta.url).pathname],{stdio:'inherit'});if(result.status!==0)process.exit(result.status??1);}}
console.log('All source syntax checks passed');
