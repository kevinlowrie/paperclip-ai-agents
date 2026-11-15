
export function useCompany(){return {selectedCompanyId:window.scope.companyId,companies:[{id:window.scope.companyId}],loading:window.scope.loading,error:null};}
export function useAccountIdentity(){return {userId:window.scope.userId,settled:window.scope.settled,failed:window.scope.failed};}
export async function requestResponse(path, options){
 const user=window.scope.userId, company=window.scope.companyId;
 window.calls.push({path,user,company,cache:options.cache});
 if(window.slow)await new Promise(resolve=>window.pending.push(resolve));
 if(window.fail)throw new Error('fixture unavailable');
 const data=path.endsWith('/projects')?[{id:'p1',companyId:company,name:'Project '+user}]:[{id:'i1',companyId:company,projectId:'p1',title:'Task '+user,status:'blocked'}];
 return new Response(JSON.stringify(data),{headers:{'content-type':'application/json'}});
}
