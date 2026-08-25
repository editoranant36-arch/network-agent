import "./globals.css";

export const metadata = {
  title: "WiFi Network Agent",
  description: "Authorized LAN monitoring dashboard"
};

export default function RootLayout({children}:{children:React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>;
}
