import {readdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
for(const file of await readdir(new URL('.',import.meta.url))){if(file.endsWith('.mjs')){const result=spawnSync(process.execPath,['--check',fileURLToPath(new URL(file,import.meta.url))],{stdio:'inherit'});if(result.status!==0)process.exit(result.status??1);}}
console.log('All source syntax checks passed');
