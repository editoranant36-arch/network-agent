/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  allowedDevOrigins: [
    "192.168.0.136",
    "192.168.0.*",
    "192.168.*.*",
    "10.*.*.*",
    "localhost",
    "127.0.0.1",
    "local-origin.dev",
    "*.local-origin.dev"
  ]
};

export default nextConfig;
