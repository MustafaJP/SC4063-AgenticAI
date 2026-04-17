// Shared utilities used across all pages

/**
 * Format seconds into a human-readable duration string.
 */
function formatDuration(sec) {
  if (sec == null || sec === '') return '—';
  sec = parseFloat(sec);
  if (sec < 60) return sec.toFixed(1) + 's';
  const m = Math.floor(sec / 60), s = Math.round(sec % 60);
  if (m < 60) return m + 'm ' + s + 's';
  const h = Math.floor(m / 60), rm = m % 60;
  return h + 'h ' + rm + 'm';
}
