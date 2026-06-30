import { Button } from "@/components/ui/button";
import { Download, Check } from "lucide-react";
import { usePWA } from "@/hooks/usePWA";
import { toast } from "@/hooks/use-toast";

export const PWAInstallButton = () => {
  const { isInstallable, isInstalled, installApp } = usePWA();

  if (isInstalled) {
    return (
      <Button variant="outline" size="sm" disabled className="text-green-600 border-green-600/20">
        <Check className="h-4 w-4 mr-2" />
        App Installed
      </Button>
    );
  }

  if (!isInstallable) return null;

  const handleInstall = async () => {
    const success = await installApp();
    if (success) {
      toast({
        title: "App Installing",
        description: "OWASP Shield Desk is being installed on your device",
      });
    } else {
      toast({
        title: "Install from browser",
        description: "Use your browser's install option to add this app to your device",
        variant: "destructive",
      });
    }
  };

  return (
    <Button onClick={handleInstall} size="sm" variant="outline" className="border-primary/20 hover:bg-primary/10">
      <Download className="h-4 w-4 mr-2" />
      Install App
    </Button>
  );
};