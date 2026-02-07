export function formatDate(date: Date): string {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(date);
}

export function getReadingTime(content: string): string {
  const wordsPerMinute = 200;
  const words = content.split(/\s+/).length;
  const minutes = Math.ceil(words / wordsPerMinute);
  return `${minutes} min read`;
}

export function getCategoryColor(category: string): string {
  const colors: Record<string, string> = {
    offensive: 'tag-offensive',
    defensive: 'tag-defensive',
    development: 'tag-development',
    forensics: 'tag-forensics',
    research: 'tag-research',
  };
  return colors[category] || 'tag-development';
}

export function getCategoryLabel(category: string): string {
  const labels: Record<string, string> = {
    offensive: 'Offensive',
    defensive: 'Defensive',
    development: 'Development',
    forensics: 'Forensics',
    research: 'Research',
  };
  return labels[category] || category;
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim();
}
