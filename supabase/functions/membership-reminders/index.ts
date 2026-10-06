import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const headers={"content-type":"application/json","access-control-allow-origin":"*","access-control-allow-headers":"authorization, x-client-info, apikey, content-type"};
Deno.serve(async (req)=>{
  if(req.method==="OPTIONS") return new Response("ok",{headers});
  if(req.method!=="POST") return new Response(JSON.stringify({error:"POST required"}),{status:405,headers});
  try{
    const url=Deno.env.get("SUPABASE_URL")!, key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
    if(!token) return new Response(JSON.stringify({error:"Unauthorized"}),{status:401,headers});
    const db=createClient(url,key);
    const {data:{user},error:userError}=await db.auth.getUser(token);
    if(userError||!user) return new Response(JSON.stringify({error:"Unauthorized"}),{status:401,headers});
    const {data:platformAdmin}=await db.from("platform_admins").select("user_id").eq("user_id",user.id).maybeSingle();
    if(!platformAdmin) return new Response(JSON.stringify({error:"Forbidden"}),{status:403,headers});
    const dates=[0,1,3,7].map(n=>{const d=new Date();d.setDate(d.getDate()+n);return d.toISOString().slice(0,10)});
    const {data:memberships,error}=await db.from("memberships").select("id,athlete_id,club_id,end_date").eq("status","active").in("end_date",dates);
    if(error) throw error;
    let created=0;
    for(const m of memberships||[]){
      const {data:athlete}=await db.from("athletes").select("full_name,email,phone").eq("id",m.athlete_id).eq("club_id",m.club_id).single();
      for(const channel of ["email","whatsapp","sms"]){
        const {data:existing}=await db.from("notifications").select("id").eq("athlete_id",m.athlete_id).eq("club_id",m.club_id).eq("channel",channel).eq("template","membership_expiring").gte("created_at",new Date(Date.now()-86400000).toISOString()).limit(1);
        if(!existing?.length){
          const {error:insertError}=await db.from("notifications").insert({athlete_id:m.athlete_id,club_id:m.club_id,channel,template:"membership_expiring",scheduled_for:new Date().toISOString(),status:"pending",payload:{membership_id:m.id,end_date:m.end_date,full_name:athlete?.full_name,email:athlete?.email,phone:athlete?.phone}});
          if(insertError) throw insertError;
          created++;
        }
      }
    }
    return new Response(JSON.stringify({ok:true,checked:(memberships||[]).length,created}),{headers});
  }catch(e){return new Response(JSON.stringify({error:e instanceof Error?e.message:"Internal error"}),{status:500,headers});}
});