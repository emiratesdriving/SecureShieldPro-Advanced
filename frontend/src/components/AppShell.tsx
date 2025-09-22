'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import ChatDock from './ChatDock';
import { 
  ShieldCheckIcon, 
  HomeIcon, 
  DocumentChartBarIcon,
  ExclamationTriangleIcon,
  CogIcon,
  BellIcon,
  UserIcon,
  ArrowLeftOnRectangleIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  Bars3Icon,
  XMarkIcon,
  ChevronDownIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  FireIcon
} from '@heroicons/react/24/outline';

interface SidebarProps {
  children: React.ReactNode;
}

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
  { name: 'Enhanced Analysis', href: '/analysis', icon: ShieldCheckIcon },
  { name: 'AI Threat Detection', href: '/threat-detection', icon: FireIcon },
  { name: 'Vulnerability Management', href: '/vulnerability-management', icon: ShieldExclamationIcon },
  { name: 'SOAR Platform', href: '/soar', icon: CogIcon },
  { name: 'Vulnerability Scans', href: '/scans', icon: ExclamationTriangleIcon },
  { name: 'Security Findings', href: '/findings', icon: DocumentChartBarIcon },
  { name: 'Compliance Reports', href: '/compliance', icon: DocumentChartBarIcon },
  { name: 'Settings', href: '/settings', icon: CogIcon },
];

const AppShell: React.FC<SidebarProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const { logout, user } = useAuth();
  const userMenuRef = useRef<HTMLDivElement>(null);

  const handleLogout = () => {
    // Use the auth context to handle logout
    logout();
    
    // The AuthWrapper will handle the redirect automatically
    // No need to manually redirect here
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900">
      {/* Backdrop blur effect */}
      <div className="fixed inset-0 bg-gradient-to-br from-slate-900/90 via-blue-900/90 to-indigo-900/90 backdrop-blur-sm"></div>
      
      {/* Mobile sidebar */}
      <div className={`relative z-50 lg:hidden ${sidebarOpen ? '' : 'hidden'}`}>
        <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm" onClick={() => setSidebarOpen(false)} />
        
        <div className="fixed inset-y-0 left-0 z-50 w-64 bg-white/10 backdrop-blur-xl border-r border-white/20">
          <div className="flex h-16 shrink-0 items-center justify-between px-6">
            <div className="flex items-center">
              <ShieldCheckIcon className="h-8 w-8 text-blue-400" />
              <span className="ml-2 text-xl font-bold text-white">SecureShield Pro</span>
            </div>
            <button
              type="button"
              className="text-gray-300 hover:text-white"
              onClick={() => setSidebarOpen(false)}
              aria-label="Close sidebar"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>
          <nav className="mt-6 px-3">
            <ul className="space-y-1">
              {navigation.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <li key={item.name}>
                    <Link
                      href={item.href}
                      className={`group flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-blue-500/20 text-blue-300 shadow-lg shadow-blue-500/20'
                          : 'text-gray-300 hover:bg-white/10 hover:text-white'
                      }`}
                    >
                      <item.icon className="mr-3 h-5 w-5" />
                      {item.name}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className={`hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:flex-col transition-all duration-300 ${
        collapsed ? 'lg:w-16' : 'lg:w-64'
      }`}>
        <div className="flex grow flex-col gap-y-5 bg-white/10 backdrop-blur-xl border-r border-white/20 px-6 pb-4">
          <div className="flex h-16 shrink-0 items-center justify-between">
            {!collapsed && (
              <div className="flex items-center">
                <ShieldCheckIcon className="h-8 w-8 text-blue-400" />
                <span className="ml-2 text-xl font-bold text-white">SecureShield Pro</span>
              </div>
            )}
            {collapsed && (
              <ShieldCheckIcon className="h-8 w-8 text-blue-400 mx-auto" />
            )}
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="text-gray-300 hover:text-white transition-colors"
            >
              {collapsed ? (
                <ChevronRightIcon className="h-5 w-5" />
              ) : (
                <ChevronLeftIcon className="h-5 w-5" />
              )}
            </button>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul className="flex flex-1 flex-col gap-y-2">
              {navigation.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <li key={item.name}>
                    <Link
                      href={item.href}
                      className={`group flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-blue-500/20 text-blue-300 shadow-lg shadow-blue-500/20'
                          : 'text-gray-300 hover:bg-white/10 hover:text-white'
                      }`}
                      title={collapsed ? item.name : undefined}
                    >
                      <item.icon className={`h-5 w-5 ${collapsed ? 'mx-auto' : 'mr-3'}`} />
                      {!collapsed && item.name}
                    </Link>
                  </li>
                );
              })}
            </ul>
            <div className="mt-auto">
              <div className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between'} rounded-lg bg-white/5 p-3 backdrop-blur-sm`}>
                {!collapsed && (
                  <div className="flex items-center">
                    <div className="h-8 w-8 rounded-full bg-gradient-to-r from-blue-400 to-purple-500 flex items-center justify-center">
                      <UserIcon className="h-4 w-4 text-white" />
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-white">
                        {user?.email?.split('@')[0] || 'Admin'}
                      </p>
                      <p className="text-xs text-gray-400">{user?.email || 'admin@company.com'}</p>
                    </div>
                  </div>
                )}
                <button 
                  className="text-gray-400 hover:text-white transition-colors"
                  onClick={handleLogout}
                  title="Sign Out"
                >
                  <ArrowLeftOnRectangleIcon className="h-5 w-5" />
                </button>
              </div>
            </div>
          </nav>
        </div>
      </div>

      {/* Main content */}
      <div className={`lg:pl-64 transition-all duration-300 ${collapsed ? 'lg:pl-16' : ''}`}>
        <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-white/20 bg-white/10 backdrop-blur-xl px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
          <button
            type="button"
            className="-m-2.5 p-2.5 text-gray-300 hover:text-white lg:hidden"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open sidebar"
          >
            <Bars3Icon className="h-6 w-6" />
          </button>

          <div className="flex flex-1 gap-x-4 justify-between items-center">
            <div className="flex items-center gap-x-4">
              <h1 className="text-lg font-semibold text-white">
                {navigation.find(item => item.href === pathname)?.name || 'Dashboard'}
              </h1>
            </div>
            
            <div className="flex items-center gap-x-4">
              <button 
                className="relative p-2 text-gray-300 hover:text-white transition-colors"
                aria-label="Notifications"
              >
                <BellIcon className="h-6 w-6" />
                <span className="absolute top-0 right-0 h-2 w-2 bg-red-500 rounded-full"></span>
              </button>
              
              <div className="h-6 w-px bg-white/20" />
              
              <div className="relative" ref={userMenuRef}>
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex items-center gap-x-2 hover:bg-white/10 rounded-lg p-2 transition-colors"
                >
                  <div className="h-8 w-8 rounded-full bg-gradient-to-r from-blue-400 to-purple-500 flex items-center justify-center">
                    <UserIcon className="h-4 w-4 text-white" />
                  </div>
                  <span className="hidden sm:block text-sm text-white">
                    {user?.email?.split('@')[0] || 'Admin'}
                  </span>
                  <ChevronDownIcon className="h-4 w-4 text-gray-400" />
                </button>

                {/* User Dropdown Menu */}
                {userMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-white/10 backdrop-blur-xl border border-white/20 rounded-lg shadow-lg">
                    <div className="py-2">
                      <Link
                        href="/settings"
                        className="flex items-center px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white"
                        onClick={() => setUserMenuOpen(false)}
                      >
                        <CogIcon className="h-4 w-4 mr-3" />
                        Settings
                      </Link>
                      <button
                        onClick={() => {
                          setUserMenuOpen(false);
                          handleLogout();
                        }}
                        className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white"
                      >
                        <ArrowLeftOnRectangleIcon className="h-4 w-4 mr-3" />
                        Sign Out
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <main className="py-6 px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="mx-auto max-w-7xl">
            {children}
          </div>
        </main>
        
        {/* AI Chat Dock */}
        <ChatDock />
      </div>
    </div>
  );
};

export default AppShell;