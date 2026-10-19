import DOMPurify from 'dompurify';
import { marked } from 'marked';

/** Render untrusted model text for HTML insertion. Never modify the result as HTML. */
export function renderMarkdown(content: string): string {
  // DOMPurify returns the original input on unsupported browsers. Fail closed.
  if (!DOMPurify.isSupported) return '';

  const html = marked.parse(content, { async: false, breaks: true, gfm: true });
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'strong', 'em', 'b', 'i', 's', 'del', 'blockquote', 'pre', 'code',
      'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'a',
    ],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    // Only explicit HTTP(S) links. No relative paths, custom schemes, or embeds.
    ALLOWED_URI_REGEXP: /^https?:\/\//i,
  });
}
