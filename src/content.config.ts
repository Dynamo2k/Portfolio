import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/blog" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()),
    image: z.string().optional(),
    author: z.string().default('Rana Uzair Ahmad'),
    featured: z.boolean().default(false),
    readTime: z.string().optional(),
    difficulty: z.string().optional(),
    imageAlt: z.string().optional(),
    imagePrompt: z.string().optional(),
  }),
});

const projects = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/projects" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()),
    image: z.string().optional(),
    github: z.string().optional(),
    stars: z.number().default(0),
    featured: z.boolean().default(false),
  }),
});

const ctf = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/ctf" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()),
    image: z.string().optional(),
    platform: z.string().optional(),
    difficulty: z.string().optional(),
  }),
});

export const collections = { blog, projects, ctf };
