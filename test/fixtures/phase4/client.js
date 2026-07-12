import { createClient } from "@supabase/supabase-js";
// service role shipped to browser
const c = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);
