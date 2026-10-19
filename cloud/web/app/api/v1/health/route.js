import { live } from "../../../../lib/public-contract.mjs";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export function GET() { return live(); }
