import { createHash } from 'node:crypto';

// Identical to vault_recovery.note_hash: UTF-8 byte lengths disambiguate title and content.
export function noteContentHash(title, content) {
  if (typeof title !== 'string' || typeof content !== 'string') throw new TypeError('invalid_note_content');
  return createHash('sha256').update(`${Buffer.byteLength(title, 'utf8')}:${title}${Buffer.byteLength(content, 'utf8')}:${content}`, 'utf8').digest('hex');
}
