import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "VulnSightAI | Military Grade Analysis",
  description: "Advanced Vulnerability Assessment Framework",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-neutral-950 text-white m-0 p-0 antialiased`}>
        {children}
      </body>
    </html>
  );
}
