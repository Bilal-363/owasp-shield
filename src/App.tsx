import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { Header } from "@/components/header";
import { AuthProvider } from "@/hooks/useAuth";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { PWAInstallModal } from "@/components/PWAInstallModal";
import { useServiceWorker } from "@/hooks/useServiceWorker";
import { ScanOrchestratorProvider } from "@/hooks/useScanOrchestrator";
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import Scanner from "./pages/Scanner";
import Results from "./pages/Results";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Guide from "./pages/Guide";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => {
  useServiceWorker();
  
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <PWAInstallModal />
        <BrowserRouter>
        <AuthProvider>
          <ScanOrchestratorProvider>
            <Routes>
              <Route path="/auth" element={<Auth />} />
              <Route path="/*" element={
                <ProtectedRoute>
                  <SidebarProvider>
                    <div className="min-h-screen flex w-full bg-background">
                      <AppSidebar />
                      <div className="flex-1 flex flex-col">
                        <Header />
                        <main className="flex-1">
                          <Routes>
                            <Route path="/" element={<Index />} />
                            <Route path="/scanner" element={<Scanner />} />
                            <Route path="/results" element={<Results />} />
                            <Route path="/reports" element={<Reports />} />
                            <Route path="/guide" element={<Guide />} />
                            <Route path="/settings" element={<Settings />} />
                            <Route path="*" element={<NotFound />} />
                          </Routes>
                        </main>
                      </div>
                    </div>
                  </SidebarProvider>
                </ProtectedRoute>
              } />
            </Routes>
          </ScanOrchestratorProvider>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
  );
};

export default App;