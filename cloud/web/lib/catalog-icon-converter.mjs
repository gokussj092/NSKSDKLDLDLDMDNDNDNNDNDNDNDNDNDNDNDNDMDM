/** Raster normalization shared by startup preparation and the runtime fallback. */
import {createRequire} from "node:module";
const require=createRequire(import.meta.url);
export const MAX_ICON_BYTES=2*1024*1024;
export const MAX_PNG_BYTES=4*1024*1024;
export const isPng=bytes=>bytes.length>=45 && bytes.subarray(0,8).toString("hex")==="89504e470d0a1a0a" &&
  bytes.readUInt32BE(8)===13 && bytes.toString("ascii",12,16)==="IHDR" &&
  bytes.readUInt32BE(16)>0 && bytes.readUInt32BE(20)>0 &&
  bytes.readUInt32BE(16)<=4096 && bytes.readUInt32BE(20)<=4096 &&
  bytes.readUInt32BE(16)*bytes.readUInt32BE(20)<=4*1024*1024 &&
  bytes.subarray(-12).toString("hex")==="0000000049454e44ae426082";

export async function convertIconToPng(bytes) {
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>MAX_ICON_BYTES)throw Error("INVALID_ORIGINAL_ICON");
  const sharp=require("sharp");
  const image=sharp(bytes,{limitInputPixels:4*1024*1024,failOn:"warning",animated:false});
  const metadata=await image.metadata();
  if(!["png","jpeg","webp","gif","avif","heif"].includes(metadata.format)||
     !metadata.width||!metadata.height||metadata.width>4096||metadata.height>4096||
     (metadata.pages??1)!==1)throw Error("INVALID_ORIGINAL_ICON");
  // Preserve valid original PNG bytes, including existing content hashes.
  if(isPng(bytes)){await image.raw().toBuffer();return bytes;}
  const result=await image.png({compressionLevel:9,adaptiveFiltering:false,palette:false}).toBuffer();
  if(!isPng(result)||result.length>MAX_PNG_BYTES)throw Error("INVALID_ORIGINAL_ICON");
  return result;
}
