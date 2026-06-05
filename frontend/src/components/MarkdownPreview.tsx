/**
 * MarkdownPreview — VS Code-like markdown renderer for .md CTI reports.
 *
 * Supports GFM (GitHub Flavored Markdown):
 *   headings, bold, italic, strikethrough, inline code, fenced code blocks,
 *   blockquotes, ordered/unordered/task lists, tables, horizontal rules,
 *   and auto-linked URLs.
 *
 * Styling is injected as a scoped <style> block so no external CSS file is
 * needed, and all values use the app's CSS custom properties so the preview
 * automatically adapts to the current theme (warm / ember / dark / etc.).
 *
 * Using a CSS approach avoids all react-markdown v9 TypeScript type issues
 * with custom component renderers.
 */
import ReactMarkdown from 'react-markdown'
import remarkGfm    from 'remark-gfm'

// ── Scoped styles ─────────────────────────────────────────────────────────────
// All selectors are prefixed with .md-preview so they never leak out.

const STYLES = `
  .md-preview {
    font-family: 'Source Serif 4', Georgia, serif;
    font-size: 15px;
    line-height: 1.72;
    color: var(--ink-2);
  }

  /* ── Headings ─────────────────────────────────────────────────────── */
  .md-preview h1 {
    font-size: 28px; font-weight: 700; line-height: 1.25;
    color: var(--ink); margin: 0 0 18px;
    border-bottom: 1px solid var(--rule); padding-bottom: 10px;
  }
  .md-preview h2 {
    font-size: 22px; font-weight: 700; line-height: 1.3;
    color: var(--ink); margin: 32px 0 12px;
    border-bottom: 1px solid var(--rule-soft); padding-bottom: 6px;
  }
  .md-preview h3 {
    font-size: 18px; font-weight: 600; line-height: 1.35;
    color: var(--ink); margin: 24px 0 8px;
  }
  .md-preview h4 {
    font-size: 15px; font-weight: 600; line-height: 1.4;
    color: var(--ink); margin: 20px 0 6px;
  }
  .md-preview h5 {
    font-size: 13px; font-weight: 600; line-height: 1.45;
    color: var(--ink); margin: 16px 0 4px;
  }
  .md-preview h6 {
    font-size: 12px; font-weight: 600; line-height: 1.5;
    color: var(--ink-3); margin: 14px 0 4px;
  }

  /* ── Paragraphs ───────────────────────────────────────────────────── */
  .md-preview p { margin: 0 0 14px; }

  /* ── Inline code ──────────────────────────────────────────────────── */
  .md-preview code {
    font-family: 'JetBrains Mono', ui-monospace, 'Cascadia Code', Consolas, monospace;
    font-size: 0.875em;
    background: var(--bg-soft);
    border: 1px solid var(--rule-soft);
    border-radius: 4px;
    padding: 1px 5px;
    color: var(--accent);
  }

  /* ── Code blocks ──────────────────────────────────────────────────── */
  .md-preview pre {
    font-family: 'JetBrains Mono', ui-monospace, 'Cascadia Code', Consolas, monospace;
    font-size: 13px;
    line-height: 1.6;
    background: var(--bg-soft);
    border: 1px solid var(--rule);
    border-radius: 8px;
    padding: 14px 18px;
    overflow-x: auto;
    margin: 0 0 16px;
    color: var(--ink);
    white-space: pre;
  }
  /* Reset inline-code style inside a code block */
  .md-preview pre code {
    background: none;
    border: none;
    padding: 0;
    color: inherit;
    font-size: inherit;
    border-radius: 0;
  }

  /* ── Blockquotes ──────────────────────────────────────────────────── */
  .md-preview blockquote {
    border-left: 3px solid var(--accent);
    background: color-mix(in oklab, var(--accent) 6%, var(--bg-soft));
    border-radius: 0 6px 6px 0;
    margin: 0 0 16px;
    padding: 10px 16px;
    color: var(--ink-3);
    font-style: italic;
  }
  .md-preview blockquote p { margin: 0; }

  /* ── Lists ────────────────────────────────────────────────────────── */
  .md-preview ul, .md-preview ol {
    margin: 0 0 14px;
    padding-left: 24px;
  }
  .md-preview li { margin-bottom: 3px; }

  /* Task list items (GFM [ ] / [x]) */
  .md-preview input[type="checkbox"] {
    accent-color: var(--accent);
    margin-right: 6px;
    vertical-align: middle;
  }

  /* ── Tables ───────────────────────────────────────────────────────── */
  .md-preview table {
    border-collapse: collapse;
    width: 100%;
    font-size: 14px;
    line-height: 1.5;
    margin: 0 0 16px;
  }
  .md-preview th {
    border: 1px solid var(--rule);
    padding: 7px 12px;
    font-weight: 600;
    color: var(--ink);
    background: var(--bg-soft);
    white-space: nowrap;
  }
  .md-preview td {
    border: 1px solid var(--rule);
    padding: 6px 12px;
    color: var(--ink-2);
    vertical-align: top;
  }
  .md-preview tbody tr:nth-child(even) {
    background: color-mix(in oklab, var(--bg-soft) 60%, transparent);
  }

  /* ── Horizontal rule ──────────────────────────────────────────────── */
  .md-preview hr {
    border: none;
    border-top: 1px solid var(--rule);
    margin: 24px 0;
  }

  /* ── Links ────────────────────────────────────────────────────────── */
  .md-preview a {
    color: var(--accent);
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .md-preview a:hover { opacity: 0.8; }

  /* ── Emphasis ─────────────────────────────────────────────────────── */
  .md-preview strong { font-weight: 700; color: var(--ink); }
  .md-preview em     { font-style: italic; }
  .md-preview del    { color: var(--ink-4); text-decoration: line-through; }

  /* ── Images ───────────────────────────────────────────────────────── */
  .md-preview img {
    max-width: 100%;
    border-radius: 6px;
    border: 1px solid var(--rule);
    margin: 8px 0;
    display: block;
  }
`

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  source: string
}

export default function MarkdownPreview({ source }: Props) {
  return (
    <>
      {/* Inject scoped styles once — React deduplicates identical style tags */}
      <style>{STYLES}</style>

      <div
        className="md-preview"
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '32px 56px 60px',
          minWidth: 0,
        }}
      >
        <ReactMarkdown remarkPlugins={[remarkGfm]}>
          {source}
        </ReactMarkdown>
      </div>
    </>
  )
}
