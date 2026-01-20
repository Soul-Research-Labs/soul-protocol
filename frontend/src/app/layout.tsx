import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: {
    default: 'PIL Protocol - Privacy Interoperability Layer',
    template: '%s | PIL Protocol',
  },
  description: 'Self-authenticating confidential containers with embedded ZK proofs for seamless cross-chain privacy-preserving operations.',
  keywords: ['privacy', 'blockchain', 'cross-chain', 'zero-knowledge', 'ethereum', 'aztec', 'zk-proofs'],
  authors: [{ name: 'PIL Protocol Team' }],
  openGraph: {
    title: 'PIL Protocol - Privacy Interoperability Layer',
    description: 'Self-authenticating confidential containers with embedded ZK proofs for seamless cross-chain privacy-preserving operations.',
    type: 'website',
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'PIL Protocol',
    description: 'Privacy Interoperability Layer for cross-chain operations',
  },
  robots: {
    index: true,
    follow: true,
  },
};

export const viewport: Viewport = {
  themeColor: '#6366f1',
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body className={`${inter.className} ${inter.variable} antialiased`}>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}
