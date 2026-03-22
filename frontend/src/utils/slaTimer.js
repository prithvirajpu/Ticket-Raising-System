export const getSlaTimer=(deadline)=>{
    if (!deadline) return {text:'N/A', status: "none"}

    const now=new Date()
    const end=new Date(deadline)
     
    const diff=end-now;
    const absDiff=Math.abs(diff)

    const minutes=Math.floor(absDiff/60000)
    const hours= Math.floor(minutes/60)
    const mins= minutes%60

    if (diff > 0) {
    return {
      text: `${hours}h ${mins}m left`,
      status: "on_time"
    };
  } else {
    return {
      text: `Breached ${hours}h ${mins}m ago`,
      status: "breached"
    };
  }

}