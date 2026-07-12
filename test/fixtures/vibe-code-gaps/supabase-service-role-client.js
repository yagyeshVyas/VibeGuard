// Supabase createClient with service_role key in a client component
import { createClient } from '@supabase/supabase-js';

const supabase = createClient('https://xyzcompany.supabase.co', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiService_role_key_fake');

export default supabase;