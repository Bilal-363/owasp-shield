import { NavLink, useLocation } from "react-router-dom";
import { Shield, Scan, FileText, BarChart3, Settings, Home, BookOpen } from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";

const navigation = [
  { title: "Home", url: "/", icon: Home },
  { title: "Scanner", url: "/scanner", icon: Scan },
  { title: "Results", url: "/results", icon: BarChart3 },
  { title: "Reports", url: "/reports", icon: FileText },
  { title: "Guide", url: "/guide", icon: BookOpen },
  { title: "Settings", url: "/settings", icon: Settings },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const location = useLocation();
  const collapsed = state === "collapsed";

  const isActive = (path: string) => location.pathname === path;
  const getNavClass = (active: boolean) =>
    active
      ? "bg-primary/10 text-primary border-r-2 border-primary"
      : "hover:bg-accent/50";

  return (
    <Sidebar className={collapsed ? "w-16" : "w-64"} collapsible="icon">
      <SidebarContent className="bg-card border-r border-border">
        <div className="p-4 border-b border-border">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            {!collapsed && (
              <div>
                <h2 className="font-bold text-lg">OWASP Shield</h2>
                <p className="text-sm text-muted-foreground">Security Scanner</p>
              </div>
            )}
          </div>
        </div>

        <SidebarGroup>
          <SidebarGroupLabel className="px-4 py-2 text-xs uppercase tracking-wider text-muted-foreground">
            Navigation
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navigation.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink
                      to={item.url}
                      className={`flex items-center gap-3 px-4 py-3 rounded-lg mx-2 transition-all ${getNavClass(
                        isActive(item.url)
                      )}`}
                    >
                      <item.icon className="h-5 w-5" />
                      {!collapsed && <span className="font-medium">{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}