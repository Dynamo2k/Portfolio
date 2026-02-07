# Rana Uzair Ahmad — Professional Cybersecurity Portfolio

A production-ready, professional cybersecurity portfolio built with Astro, Tailwind CSS, and MDX.

## Tech Stack

- **Framework:** [Astro](https://astro.build) — Zero-JS by default, blazing fast
- **Styling:** [Tailwind CSS](https://tailwindcss.com) — Utility-first CSS framework
- **Content:** MDX for blog posts (Markdown + components)
- **Deployment:** Configured for [Vercel](https://vercel.com)

## Getting Started

### Prerequisites

- Node.js 18+ and npm

### Installation

```bash
cd portfolio
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:4321](http://localhost:4321) in your browser.

### Build

```bash
npm run build
```

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
portfolio/
├── src/
│   ├── components/     # Reusable UI components
│   ├── layouts/        # Page layouts (Base, Blog, Project)
│   ├── pages/          # Site pages and routes
│   │   ├── blog/       # Blog posts
│   │   └── projects/   # Project pages and case studies
│   ├── styles/         # Global CSS and Tailwind imports
│   └── utils/          # Constants, helpers, and utilities
├── public/             # Static assets (images, resume, favicon)
├── astro.config.mjs    # Astro configuration
├── tailwind.config.cjs # Tailwind CSS configuration
├── tsconfig.json       # TypeScript configuration
└── vercel.json         # Vercel deployment configuration
```

## How to Add Blog Posts

1. Create a new `.astro` file in `src/pages/blog/`
2. Use the `BlogLayout` layout:

```astro
---
import BlogLayout from '../../layouts/BlogLayout.astro';
---

<BlogLayout
  title="Your Post Title"
  date="February 7, 2026"
  readTime="10 min read"
  category="Technical Guide"
>

## Your Markdown Content Here

Write your blog post using standard Markdown syntax.

</BlogLayout>
```

3. Add the post to the blog listing in `src/pages/blog/index.astro`

## How to Add Projects

1. Add project data to `src/utils/constants.ts` in `FEATURED_PROJECTS` or `ADDITIONAL_PROJECTS`
2. For a case study page, create a new `.astro` file in `src/pages/projects/`
3. Use the `ProjectLayout` layout

## How to Update the Resume

1. Replace `public/Rana_Uzair_Ahmad_Resume.pdf` with the updated PDF
2. The download button will automatically serve the new file

## How to Deploy

### Vercel (Recommended)

```bash
npm install -g vercel
vercel
```

Or connect your GitHub repository to Vercel for automatic deployments.

### GitHub Pages

Configure the `site` property in `astro.config.mjs` and set up GitHub Actions for deployment.

## Features

- Professional dark theme with cybersecurity-inspired design
- Fully responsive (mobile, tablet, desktop)
- WCAG AA accessible
- SEO optimized with meta tags and structured data
- Fast performance with Astro's zero-JS approach
- Filterable project gallery
- Blog with syntax highlighting
- Contact form integration
- Resume download on every page
- Keyboard navigable with skip links

## License

MIT License
