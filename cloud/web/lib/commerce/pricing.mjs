// Commercial planning only. This does not add a checkout surcharge or promise
// a settlement amount: FX, cross-border and dispute fees can differ.
export function estimateRetail(targetNet,{rateBps,fixedCents,feeTaxBps=0,salesTaxBps=0}){
  if(![targetNet,rateBps,fixedCents,feeTaxBps,salesTaxBps].every(Number.isSafeInteger)||targetNet<1||
    targetNet>1000000||rateBps<0||rateBps>3000||fixedCents<0||fixedCents>100000||
    feeTaxBps<0||feeTaxBps>3000||salesTaxBps<0||salesTaxBps>3000)throw Error('INVALID_FEE_ESTIMATE');
  const net=base=>{const total=base+Math.round(base*salesTaxBps/10000);
    const fee=Math.ceil((total*rateBps/10000+fixedCents)*(1+feeTaxBps/10000));return base-fee;};
  let low=targetNet,high=targetNet*4+fixedCents*4;
  while(low<high){const mid=Math.floor((low+high)/2);if(net(mid)>=targetNet)high=mid;else low=mid+1;}
  return {retailCents:low,estimatedNetCents:net(low)};
}
