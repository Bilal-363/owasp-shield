import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Smartphone, Download, X, Shield } from "lucide-react";
import { usePWA } from "@/hooks/usePWA";

export const PWAInstallModal = () => {
  const { showInstallModal, installApp, dismissInstallModal, isInstallable } = usePWA();

  if (!showInstallModal || !isInstallable) return null;

  const handleInstall = async () => {
    const success = await installApp();
    if (!success) {
      // If automatic install fails, show manual instructions
      console.log('Manual install instructions needed');
    }
  };

  return (
    <Dialog open={showInstallModal} onOpenChange={dismissInstallModal}>
      <DialogContent className="sm:max-w-md border border-border bg-card">
        <DialogHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-full bg-primary/10 border border-primary/20">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <DialogTitle className="text-xl font-semibold text-foreground">
            Install OWASP Shield Desk
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Get faster access and enhanced performance by installing the app on your device.
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="flex items-center gap-2 p-3 rounded-lg bg-secondary/50 border border-border">
              <Smartphone className="h-4 w-4 text-primary" />
              <span className="text-foreground">Works Offline</span>
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg bg-secondary/50 border border-border">
              <Download className="h-4 w-4 text-primary" />
              <span className="text-foreground">Faster Loading</span>
            </div>
          </div>
          
          <div className="flex gap-2">
            <Button onClick={handleInstall} className="flex-1 bg-primary hover:bg-primary/90">
              <Download className="h-4 w-4 mr-2" />
              Install App
            </Button>
            <Button variant="outline" onClick={dismissInstallModal} size="icon">
              <X className="h-4 w-4" />
            </Button>
          </div>
          
          <p className="text-xs text-muted-foreground text-center">
            You can always install later from your browser menu
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
};