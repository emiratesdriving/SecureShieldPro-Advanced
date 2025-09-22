import './globals.css'
import { Inter } from '@next/font/google'
import { Providers } from './providers'
import { AuthProvider } from '@/contexts/AuthContext'
import AuthWrapper from '@/components/AuthWrapper'
import ConditionalAppShell from '@/components/ConditionalAppShell'
import React from 'react'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'SecureShield Pro - Advanced Security Platform',
  description: 'Professional security platform with AI-powered threat detection, vulnerability scanning, and compliance management.',
  keywords: 'security, SAST, DAST, vulnerability, scanning, AI, threat analysis, compliance',
  authors: [{ name: 'SecureShield Pro Team' }],
  robots: 'index, follow',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#0ea5e9" />
      </head>
      <body className={`${inter.className} antialiased`}>
        <Providers>
          <AuthProvider>
            <AuthWrapper>
              <ConditionalAppShell>
                {children}
              </ConditionalAppShell>
            </AuthWrapper>
          </AuthProvider>
        </Providers>
      </body>
    </html>
  )
}