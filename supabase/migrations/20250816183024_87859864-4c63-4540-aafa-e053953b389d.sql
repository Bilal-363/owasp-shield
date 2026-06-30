-- Create user profiles table
CREATE TABLE public.profiles (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  full_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create scans table
CREATE TABLE public.scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
  scan_type TEXT NOT NULL DEFAULT 'full',
  tools_used TEXT[] DEFAULT ARRAY[]::TEXT[],
  started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  total_findings INTEGER DEFAULT 0,
  high_risk_findings INTEGER DEFAULT 0,
  medium_risk_findings INTEGER DEFAULT 0,
  low_risk_findings INTEGER DEFAULT 0,
  scan_config JSONB DEFAULT '{}'::JSONB,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create findings table
CREATE TABLE public.findings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  owasp_category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('High', 'Medium', 'Low', 'Info')),
  title TEXT NOT NULL,
  description TEXT,
  evidence TEXT,
  recommendation TEXT,
  affected_url TEXT,
  parameters TEXT[],
  cwe_id TEXT,
  cvss_score DECIMAL(3,1),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create scan_reports table
CREATE TABLE public.scan_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK (format IN ('pdf', 'html', 'json', 'csv')),
  file_path TEXT,
  file_size INTEGER,
  generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create scan_logs table for real-time updates
CREATE TABLE public.scan_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'warning', 'error', 'debug')),
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_logs ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for profiles
CREATE POLICY "Users can view their own profile" 
ON public.profiles FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own profile" 
ON public.profiles FOR UPDATE 
USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own profile" 
ON public.profiles FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- Create RLS policies for scans
CREATE POLICY "Users can view their own scans" 
ON public.scans FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own scans" 
ON public.scans FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans" 
ON public.scans FOR UPDATE 
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own scans" 
ON public.scans FOR DELETE 
USING (auth.uid() = user_id);

-- Create RLS policies for findings
CREATE POLICY "Users can view findings for their scans" 
ON public.findings FOR SELECT 
USING (
  EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.id = findings.scan_id 
    AND scans.user_id = auth.uid()
  )
);

CREATE POLICY "Service can insert findings" 
ON public.findings FOR INSERT 
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.id = findings.scan_id 
    AND scans.user_id = auth.uid()
  )
);

-- Create RLS policies for scan_reports
CREATE POLICY "Users can view their own reports" 
ON public.scan_reports FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own reports" 
ON public.scan_reports FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- Create RLS policies for scan_logs
CREATE POLICY "Users can view logs for their scans" 
ON public.scan_logs FOR SELECT 
USING (
  EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.id = scan_logs.scan_id 
    AND scans.user_id = auth.uid()
  )
);

CREATE POLICY "Service can insert scan logs" 
ON public.scan_logs FOR INSERT 
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.id = scan_logs.scan_id 
    AND scans.user_id = auth.uid()
  )
);

-- Create storage buckets for reports
INSERT INTO storage.buckets (id, name, public) VALUES ('scan-reports', 'scan-reports', false);
INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);

-- Create storage policies
CREATE POLICY "Users can view their own reports" 
ON storage.objects FOR SELECT 
USING (bucket_id = 'scan-reports' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can upload their own reports" 
ON storage.objects FOR INSERT 
WITH CHECK (bucket_id = 'scan-reports' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can delete their own reports" 
ON storage.objects FOR DELETE 
USING (bucket_id = 'scan-reports' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Avatar images are publicly accessible" 
ON storage.objects FOR SELECT 
USING (bucket_id = 'avatars');

CREATE POLICY "Users can upload their own avatar" 
ON storage.objects FOR INSERT 
WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_scans_updated_at
  BEFORE UPDATE ON public.scans
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

-- Create function to handle new user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (user_id, email, full_name)
  VALUES (
    NEW.id, 
    NEW.email, 
    COALESCE(NEW.raw_user_meta_data->>'full_name', '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for new user registration
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Enable realtime for live updates
ALTER TABLE public.scans REPLICA IDENTITY FULL;
ALTER TABLE public.scan_logs REPLICA IDENTITY FULL;
ALTER TABLE public.findings REPLICA IDENTITY FULL;

-- Add tables to realtime publication
ALTER PUBLICATION supabase_realtime ADD TABLE public.scans;
ALTER PUBLICATION supabase_realtime ADD TABLE public.scan_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE public.findings;