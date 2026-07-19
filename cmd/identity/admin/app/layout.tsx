import type { Metadata, Viewport } from "next";
import { ConfirmProvider } from "@/components/ConfirmProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppToaster } from "@/components/AppToaster";
import "./globals.css";

export const metadata: Metadata = {
  title: "ApiCoreX — Platform Console",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    // Dark is the console's primary surface. The class is set here so the
    // shadcn `.dark` token overrides apply from first paint (no theme flash).
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <ThemeProvider>
          <ConfirmProvider>
            {children}
            <AppToaster />
          </ConfirmProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
