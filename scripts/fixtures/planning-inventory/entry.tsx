
import React from 'react'; import { createRoot } from 'react-dom/client'; import { flushSync } from 'react-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PlanningInventory } from '../../../ui/src/pages/PlanningInventory';
window.scope={userId:'one',companyId:'c1',settled:true,failed:false,loading:false};
window.pending=[];window.slow=false;window.fail=false;window.calls=[];
const root=createRoot(document.getElementById('root'));
const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
window.change=changes=>{Object.assign(window.scope,changes);flushSync(()=>root.render(<QueryClientProvider client={client}><PlanningInventory/></QueryClientProvider>));};
window.change({});
