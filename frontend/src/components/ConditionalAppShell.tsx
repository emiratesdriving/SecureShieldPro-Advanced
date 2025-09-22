'use client';

import { usePathname } from 'next/navigation';
import AppShell from './AppShell';

interface ConditionalAppShellProps {
  children: React.ReactNode;
}

export default function ConditionalAppShell({ children }: ConditionalAppShellProps) {
  const pathname = usePathname();
  
  // Routes that should not have AppShell (auth pages)
  const authRoutes = ['/auth/login', '/auth/register'];
  const isAuthRoute = authRoutes.includes(pathname);

  if (isAuthRoute) {
    return <>{children}</>;
  }

  return <AppShell>{children}</AppShell>;
}