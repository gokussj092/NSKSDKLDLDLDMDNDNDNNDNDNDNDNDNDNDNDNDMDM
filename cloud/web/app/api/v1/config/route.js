import { clientConfig } from "../../../../lib/public-contract.mjs";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export function GET() { return clientConfig(); }
