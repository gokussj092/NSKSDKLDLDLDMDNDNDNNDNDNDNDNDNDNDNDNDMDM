/** Bounded stdin/stdout worker: no shell, URLs, or writable runtime paths. */
import {convertIconToPng,MAX_ICON_BYTES} from "../lib/catalog-icon-converter.mjs";
try {
  const chunks=[];let size=0;
  for await(const chunk of process.stdin){size+=chunk.length;if(size>MAX_ICON_BYTES)throw Error("size");chunks.push(chunk);}
  process.stdout.write(await convertIconToPng(Buffer.concat(chunks)));
}catch{process.stderr.write("INVALID_ORIGINAL_ICON\n");process.exitCode=1;}
