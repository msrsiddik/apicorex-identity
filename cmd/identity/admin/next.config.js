/** @type {import('next').NextConfig} */
const nextConfig = {
  // Emit a fully static site into ./out — no Node server at runtime. The Go
  // binary embeds ./out and serves it under /admin.
  output: "export",

  // Everything (the HTML entry and every _next/* asset) is served beneath the
  // /console route. NOTE: not /admin — Core's gateway firewall blocks the
  // /admin/ prefix as a reserved path, which would 403 every asset. /console is
  // an ordinary (public) plugin route Core proxies normally. basePath rewrites
  // internal links; assetPrefix rewrites asset URLs — both must be /console.
  basePath: "/console",
  assetPrefix: "/console",

  // No Next.js image optimizer at runtime (there's no server), so serve images
  // as-is. We don't use next/image today, but this keeps export from erroring
  // if one is ever added.
  images: { unoptimized: true },

  // Emit /admin/foo/index.html rather than /admin/foo.html, so a plain static
  // file server (our Go wildcard handler) can resolve directory-style paths.
  trailingSlash: true,
};

module.exports = nextConfig;
