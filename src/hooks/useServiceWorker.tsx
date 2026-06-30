import { useEffect } from 'react';
import { toast } from '@/hooks/use-toast';

export const useServiceWorker = () => {
  useEffect(() => {
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
          .then((registration) => {
            console.log('SW registered: ', registration);
            
            // Check for updates
            registration.addEventListener('updatefound', () => {
              const newWorker = registration.installing;
              if (newWorker) {
                newWorker.addEventListener('statechange', () => {
                  if (newWorker.state === 'installed') {
                    if (navigator.serviceWorker.controller) {
                      // New content is available, show update notification
                      toast({
                        title: "App Updated",
                        description: "A new version is available. Refresh to update.",
                        action: (
                          <button 
                            onClick={() => window.location.reload()}
                            className="bg-primary text-primary-foreground px-3 py-1 rounded text-sm"
                          >
                            Refresh
                          </button>
                        ),
                      });
                    }
                  }
                });
              }
            });
          })
          .catch((error) => {
            console.log('SW registration failed: ', error);
          });
      });

      // Listen for service worker messages
      navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'SKIP_WAITING') {
          window.location.reload();
        }
      });
    }
  }, []);

  const updateApp = () => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        registrations.forEach((registration) => {
          registration.update();
        });
      });
    }
  };

  return { updateApp };
};